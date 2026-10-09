"""T1 behavior dataset builder and trainer (issue #617).

Synthetic wire-format captures only: they prove the pipeline (capture -> per-incarnation
records -> 23 features -> model -> record) holds together and fails closed. They say
nothing about detection quality; that needs a real capture of normal activity.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from synthaea_ml.data.behavior_dataset import load_records, records_from_events
from synthaea_ml.data.manifest import BEHAVIOR_CAPTURE_FILENAME, write_manifest
from synthaea_ml.features import t1
from synthaea_ml.registry.training_record import (
    default_dataset_name,
    load_training_record,
    verify_training_record,
)
from synthaea_ml.training import train_behavior

_START = datetime(2026, 10, 2, 10, 0, 0, tzinfo=UTC)
_END = datetime(2026, 10, 2, 11, 0, 0, tzinfo=UTC)
S = 1_000_000_000
SCENARIO = Path(__file__).resolve().parents[2] / "lab" / "scenarios" / "beacon.yaml"


def _meta(pid: int, ts: int, generation: int | None = None) -> dict:
    meta = {"pid": pid, "ppid": 1, "timestamp_ns": ts, "comm": "x"}
    if generation is not None:
        meta["process_generation"] = generation
    return meta


def _exec(pid: int, ts: int, argv: list[str], parent: tuple[str, str], generation=None) -> dict:
    return {
        "type": "exec",
        "meta": _meta(pid, ts, generation),
        "argv": argv,
        "image_path": argv[0],
        "parent_comm": parent[0],
        "parent_image_path": parent[1],
    }


def _connect(pid: int, ts: int, dport: int, generation=None) -> dict:
    return {
        "type": "connect",
        "meta": _meta(pid, ts, generation),
        "daddr": "10.0.0.1",
        "dport": dport,
    }


def _capture(n: int = 40) -> list[dict]:
    """`n` distinct benign-looking processes, a third of which also connect out."""
    events: list[dict] = []
    for i in range(n):
        pid = 1000 + i
        ts = (i + 1) * 100 * S
        events.append(
            _exec(
                pid,
                ts,
                [f"/usr/bin/tool{i}", "--flag", "x" * (i % 7 + 1)],
                ("bash", "/usr/bin/bash") if i % 2 else ("systemd", "/usr/lib/systemd/systemd"),
            )
        )
        if i % 3 == 0:
            events.append(_connect(pid, ts + S, 443 + i))
    return events


def _write_dataset(
    root: Path, events: list[dict], name: str = "linux__dev__abc__2026-10-02"
) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / BEHAVIOR_CAPTURE_FILENAME).write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )
    write_manifest(
        d,
        platform="linux",
        os_version="test",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="testhost",
        baseline_filename=BEHAVIOR_CAPTURE_FILENAME,
    )
    return d


def _run(monkeypatch: pytest.MonkeyPatch, dataset: Path, out: Path, *extra: str) -> None:
    argv = [train_behavior.TRAINING_SCRIPT, "--dataset", str(dataset), "--output-dir", str(out)]
    monkeypatch.setattr("sys.argv", [*argv, *extra])
    train_behavior.main()


# --- the dataset builder --------------------------------------------------------------


def test_one_record_per_incarnation_with_lineage_and_correlation_context(tmp_path: Path) -> None:
    d = _write_dataset(tmp_path, _capture(6))
    records = load_records(d / BEHAVIOR_CAPTURE_FILENAME)
    assert len(records) == 6
    first = records[0]
    assert first["parent_comm"] == "systemd"
    assert first["argv"][0] == "/usr/bin/tool0"
    assert len(first["correlation_features"]) == 8
    assert first["correlation_features"][1] == 1.0, "tool0 connected out (i % 3 == 0)"
    assert len(t1.extract_features(first)) == t1.FEATURE_COUNT == 23


def test_a_recycled_pid_yields_two_records_and_the_first_life_does_not_leak(
    tmp_path: Path,
) -> None:
    events = [
        _exec(7, 10 * S, ["/bin/a"], ("nginx", "/usr/sbin/nginx"), generation=1),
        _connect(7, 11 * S, 80, generation=1),
        _exec(7, 12 * S, ["/bin/b"], ("bash", "/bin/bash"), generation=2),
    ]
    d = _write_dataset(tmp_path, events)
    first, second = load_records(d / BEHAVIOR_CAPTURE_FILENAME)
    assert (first["process_generation"], second["process_generation"]) == (1, 2)
    assert first["parent_comm"] == "nginx" and second["parent_comm"] == "bash"
    assert first["correlation_features"][1] == 1.0
    assert second["correlation_features"][1] == 0.0, "the old life's connect must not leak"


def test_the_per_pid_window_gives_the_same_records_as_scanning_the_whole_capture() -> None:
    """The builder takes each window from the pid's own events (a million-event capture made
    the full scan quadratic); this is the full scan, kept here as the reference."""
    import random

    from synthaea_ml.features import correlation

    def reference(events: list[dict], window_ns: int) -> list[dict]:
        incarnations: dict[tuple[int, int | None], list[dict]] = {}
        for e in events:
            incarnations.setdefault((e["pid"], e.get("process_generation")), []).append(e)
        out = []
        for (pid, generation), own in sorted(
            incarnations.items(), key=lambda kv: (kv[0][0], kv[0][1] is None, kv[0][1] or 0)
        ):
            execs = [e for e in own if e["type"] == "exec"]
            if not execs:
                continue
            cutoff = max(e["ts_ns"] for e in own) - window_ns
            window = [e for e in events if e["ts_ns"] >= cutoff]
            features = correlation.extract_features(window, pid, generation)
            if features[-1] < 1:
                continue
            exec_event = max(execs, key=lambda e: e["ts_ns"])
            record = {k: v for k, v in exec_event.items() if k not in ("type", "ts_ns")}
            record["correlation_features"] = features
            out.append(record)
        return out

    rng = random.Random(7)
    events: list[dict] = []
    for i in range(300):
        pid = rng.choice([10, 11, 12, 13, 14])  # few pids: recycling and interleaving
        generation = rng.choice([None, 1, 2, 3])  # unstamped and stamped incarnations mixed
        ts = i * 7 * S + rng.randrange(S)
        kind = rng.choice(["exec", "connect", "fileopen", "exec"])
        event = {"type": kind, "pid": pid, "ts_ns": ts}
        if generation is not None:
            event["process_generation"] = generation
        if kind == "exec":
            event.update(argv=[f"/usr/bin/t{i % 9}"], parent_comm="bash")
        elif kind == "connect":
            event.update(daddr_v4=["10.0.0.1"], dport=443 + i % 4)
        else:
            event.update(flags=1)
        events.append(event)
    events.sort(key=lambda e: e["ts_ns"])

    for window_ns in (5 * S, 60 * S, 10_000 * S):
        assert records_from_events(events, window_ns) == reference(events, window_ns)


def test_a_process_with_no_exec_yields_no_record() -> None:
    events = [{"type": "connect", "pid": 9, "ts_ns": 1, "daddr_v4": ["1.2.3.4"], "dport": 80}]
    assert records_from_events(events) == []


def test_the_window_ends_at_the_last_event_of_the_incarnation() -> None:
    events = [
        {"type": "exec", "pid": 5, "ts_ns": 0, "argv": ["/bin/x"]},
        {"type": "connect", "pid": 5, "ts_ns": 100 * S, "daddr_v4": ["1.2.3.4"], "dport": 80},
    ]
    # A 60 s window ending at the last event (100 s) no longer contains the exec at 0.
    (record,) = records_from_events(events, window_ns=60 * S)
    assert record["correlation_features"][0] == 0.0, "spawn_count: the exec fell out"
    assert record["correlation_features"][1] == 1.0, "connect_count"
    (record,) = records_from_events(events, window_ns=200 * S)
    assert record["correlation_features"][0] == 1.0


# --- the trainer ----------------------------------------------------------------------


def test_train_behavior_end_to_end(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    d = _write_dataset(tmp_path, _capture(40))
    out = tmp_path / "model_out"
    _run(monkeypatch, d, out)

    assert (out / "model.onnx").exists()
    metadata = json.loads((out / "model_metadata.json").read_text(encoding="utf-8"))
    assert metadata["feature_bounds"]["feature_names"] == t1.FEATURE_NAMES
    assert len(metadata["feature_bounds"]["min_values"]) == 23

    record = load_training_record(out)
    assert record.training_script == "synthaea_ml/training/train_behavior.py"
    assert record.dataset_versions[0].sample_count == len(
        (d / BEHAVIOR_CAPTURE_FILENAME).read_text(encoding="utf-8").splitlines()
    )

    import onnx

    graph_input = onnx.load(str(out / "model.onnx")).graph.input[0]
    width = graph_input.type.tensor_type.shape.dim[1].dim_value
    assert width == 23, "the exported model takes the 23-feature T1 vector"


def test_train_behavior_refuses_a_capture_too_small_to_calibrate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    d = _write_dataset(tmp_path, _capture(5))
    with pytest.raises(ValueError, match="distinct behavior vectors"):
        _run(monkeypatch, d, tmp_path / "out")


def test_train_behavior_refuses_a_capture_edited_after_its_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    d = _write_dataset(tmp_path, _capture(40))
    with (d / BEHAVIOR_CAPTURE_FILENAME).open("a", encoding="utf-8") as f:
        f.write(json.dumps(_connect(1000, 99 * S, 22)) + "\n")
    with pytest.raises(ValueError, match="mismatch"):
        _run(monkeypatch, d, tmp_path / "out")


def test_the_release_gate_re_verifies_an_events_jsonl_dataset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    baselines = tmp_path / "baselines"
    d = _write_dataset(baselines, _capture(40))
    # The record names a dataset by the manifest-derived name; the gate looks it up
    # under that directory name.
    d = d.rename(baselines / default_dataset_name(d))
    out = tmp_path / "out"
    _run(monkeypatch, d, out)
    verify_training_record(out, baselines_root=baselines, scenarios_root=tmp_path)


def test_train_behavior_runs_the_t1_robustness_tier_and_records_the_card(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Wiring only: the evaluation itself is covered in `test_robustness.py`. Whether a toy
    Isolation Forest flags a given synthetic outlier is a property of the toy corpus (the
    forest cannot rank a point outside its training range as more anomalous than the range
    edge: that is what the on-device feature-bounds guard is for), so it is not asserted."""
    from synthaea_ml.registry.training_record import MutationTestResult, RobustnessCard

    calls: list[dict] = []

    def fake_evaluation(**kwargs):
        calls.append(kwargs)
        return RobustnessCard(
            scenario_name="beacon",
            scenario_yaml_sha256="0" * 64,
            tested_at="2026-10-02T10:00:00Z",
            mutation_results=[
                MutationTestResult(
                    mutation_class="parent_path",
                    intensity="heavy",
                    original_score=-0.1,
                    mutated_score=0.1,
                    score_delta=0.2,
                    threshold=0.0,
                    escaped=True,
                    seed=1,
                )
            ],
            escape_rate=1.0,
            median_score_degradation=0.2,
            worst_case_degradation=0.2,
        )

    monkeypatch.setattr(train_behavior, "run_robustness_evaluation", fake_evaluation)
    d = _write_dataset(tmp_path, _capture(40))
    malicious = tmp_path / "malicious.jsonl"
    malicious.write_text("{}\n", encoding="utf-8")
    out = tmp_path / "out"
    _run(
        monkeypatch,
        d,
        out,
        "--robustness-scenarios",
        str(SCENARIO),
        "--robustness-events",
        str(malicious),
    )
    (call,) = calls
    assert call["tier"] == "T1"
    assert call["events_source"] == malicious
    assert call["model"].n_features_in_ == 23
    (card,) = load_training_record(out).robustness_cards
    assert card.scenario_name == "beacon"
