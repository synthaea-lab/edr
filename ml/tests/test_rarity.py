"""Rarity feature and its point-in-time derivation (issue #640)."""

from __future__ import annotations

import random

import pytest

from synthaea_ml.data.common_set import DEFAULT_INTERVAL_NS, point_in_time_snapshots
from synthaea_ml.features import rarity
from synthaea_ml.features.rarity import CommonSetSnapshot

DAY = DEFAULT_INTERVAL_NS
H1 = "a" * 64
H2 = "b" * 64


def record(agent: str, day: float, sha: str | None = H1, event_type: str = "exec") -> dict:
    seconds = int(day * 86400)
    stamp = f"2026-09-{1 + seconds // 86400:02d}T{(seconds % 86400) // 3600:02d}:00:00Z"
    event = {"image_path": "/usr/bin/x", "argv": ["x"]}
    if sha is not None:
        event["sha256"] = sha
    return {"timestamp": stamp, "event_type": event_type, "event": event, "agent_id": agent}


# --- the feature ---------------------------------------------------------------------


def test_the_feature_distinguishes_rare_from_no_basis_to_say() -> None:
    snap = CommonSetSnapshot(common=frozenset({H1}), hosts_covered=10)
    assert rarity.extract_features(H1, snap, min_hosts=5) == [1.0, 1.0]  # known, common
    assert rarity.extract_features(H2, snap, min_hosts=5) == [1.0, 0.0]  # known, rare
    assert rarity.extract_features(None, snap, min_hosts=5) == [0.0, 0.0]  # no hash
    assert rarity.extract_features(H1, None, min_hosts=5) == [0.0, 0.0]  # no snapshot yet


def test_a_snapshot_over_too_few_hosts_withholds_the_evidence() -> None:
    """A fleet that just enrolled: every binary would look rare. ADR-0020 withholds it."""
    thin = CommonSetSnapshot(common=frozenset(), hosts_covered=2)
    assert rarity.extract_features(H2, thin, min_hosts=5) == [0.0, 0.0]


def test_hashes_are_normalized_like_the_servers_counters() -> None:
    snap = CommonSetSnapshot(common=frozenset({H1}), hosts_covered=9)
    assert rarity.extract_features(H1.upper(), snap, 1) == [1.0, 1.0]
    assert rarity.extract_features("not-a-hash", snap, 1) == [0.0, 0.0]
    assert rarity.extract_features(12345, snap, 1) == [0.0, 0.0]


# --- point in time ------------------------------------------------------------------


def test_no_snapshot_exists_before_the_first_boundary() -> None:
    recs = [record("a1", 0), record("a2", 0.5)]
    assert point_in_time_snapshots(recs, k=2) == [None, None]


def test_an_event_never_sees_hosts_that_ran_the_image_after_it() -> None:
    """The future leak the feature must not have: a hash that became common on day 3 is
    rare for an event on day 2."""
    recs = [
        record("a1", 0),
        record("a1", 1.5, H2),  # day 1.5: first snapshot is in force (taken at day 1)
        record("a2", 2.2),  # H1 on a second host
        record("a3", 2.4),  # H1 on a third host: common from day 3 on
        record("a4", 3.5, H2),  # after the day-3 boundary
    ]
    snaps = point_in_time_snapshots(recs, k=3)
    assert snaps[1] is not None and H1 not in snaps[1].common
    # The event right after the third host ran it still sees the day-2 snapshot.
    assert snaps[3] is not None and H1 not in snaps[3].common
    assert snaps[4] is not None and H1 in snaps[4].common


def test_the_snapshot_changes_only_at_a_boundary_not_with_every_event() -> None:
    recs = [record("a1", 0), record("a2", 0.1), record("a3", 0.2), record("a4", 1.1), record("a5", 1.2)]
    snaps = point_in_time_snapshots(recs, k=3)
    assert snaps[3] == snaps[4], "two events inside one interval share one snapshot"
    assert snaps[3] is not None and H1 in snaps[3].common
    assert snaps[3].hosts_covered == 3


def test_a_host_counts_once_however_often_it_ran_the_image() -> None:
    recs = [record("a1", 0.1 * i) for i in range(8)] + [record("a2", 1.2)]
    snaps = point_in_time_snapshots(recs, k=2)
    assert snaps[-1] is not None and H1 not in snaps[-1].common
    assert snaps[-1].hosts_covered == 1


def test_records_without_an_agent_or_a_valid_hash_add_no_host() -> None:
    recs = [
        record("a1", 0),
        {**record("a2", 0.1), "agent_id": ""},
        record("a3", 0.2, sha="zz"),
        record("a4", 0.3, event_type="connect"),
        record("a5", 1.1),
    ]
    snap = point_in_time_snapshots(recs, k=2)[-1]
    assert snap is not None and H1 not in snap.common
    assert snap.hosts_covered == 3, "a1, a3 and a4 reported; the empty agent id did not"


def test_input_order_does_not_change_the_result() -> None:
    recs = [record(f"a{i % 5}", i * 0.3, H1 if i % 3 else H2) for i in range(30)]
    expected = point_in_time_snapshots(recs, k=2)
    shuffled = list(range(len(recs)))
    random.Random(7).shuffle(shuffled)
    got = point_in_time_snapshots([recs[i] for i in shuffled], k=2)
    for position, original in enumerate(shuffled):
        assert got[position] == expected[original]


def test_a_quiet_stretch_publishes_the_same_state() -> None:
    recs = [record("a1", 0), record("a2", 0.2), record("a3", 0.4), record("a4", 9.5)]
    snaps = point_in_time_snapshots(recs, k=3)
    assert snaps[3] is not None and H1 in snaps[3].common


def test_bad_parameters_are_refused() -> None:
    with pytest.raises(ValueError):
        point_in_time_snapshots([], k=0)
    with pytest.raises(ValueError):
        point_in_time_snapshots([], interval_ns=0)


# --- the recalibration run ---------------------------------------------------------------


def _corpus(tmp_path, hosts: int = 8, days: int = 20, per_day: int = 6) -> object:
    """A synthetic site: `hosts` agents run mostly the same tools, plus per-host oddities."""
    import json

    rows: list[dict] = []
    common = [f"{i:064x}" for i in range(6)]
    for day in range(days):
        for h in range(hosts):
            for n in range(per_day):
                shared = (day + h + n) % 4 != 0
                sha = common[(h + n) % len(common)] if shared else f"{(h * 1000 + day * 10 + n):064x}"
                stamp = f"2026-09-{1 + day:02d}T{8 + n:02d}:{h:02d}:00Z"
                argv = ["/usr/bin/tool", f"--mode{n % 3}", "x" * (1 + (day + n) % 5)]
                rows.append(
                    {
                        "timestamp": stamp,
                        "event_type": "exec",
                        "agent_id": f"agent-{h}",
                        "event": {"argv": argv, "image_path": argv[0], "sha256": sha},
                    }
                )
    path = tmp_path / "corpus-v1.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_the_site_rarity_run_trains_both_models_and_records_the_effect(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    import onnx

    from synthaea_ml.registry.training_record import load_training_record
    from synthaea_ml.training import train_site_rarity

    corpus = _corpus(tmp_path)
    out = tmp_path / "site-model"
    monkeypatch.setattr(
        "sys.argv",
        [
            train_site_rarity.TRAINING_SCRIPT,
            "--site-corpus",
            str(corpus),
            "--site-name",
            "acme",
            "--output-dir",
            str(out),
            "--min-hosts",
            "3",
        ],
    )
    train_site_rarity.main()

    record = load_training_record(out)
    assert record.dataset_versions[0].name == "site-corpus-acme"
    extra = record.extra
    assert 0.0 < float(extra["rarity_known_fraction"]) <= 1.0
    for key in ("fp_rate_test_cmdline_only", "fp_rate_test_with_rarity"):
        assert 0.0 <= float(extra[key]) <= 1.0
    assert "NOT CHECKED" in extra["global_model_floor"], "the floor check is not claimed"

    graph_input = onnx.load(str(out / "model.onnx")).graph.input[0]
    assert graph_input.type.tensor_type.shape.dim[1].dim_value == 11


def test_a_corpus_too_small_for_a_time_split_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from synthaea_ml.training import train_site_rarity

    corpus = _corpus(tmp_path, hosts=2, days=2, per_day=2)
    monkeypatch.setattr(
        "sys.argv",
        [train_site_rarity.TRAINING_SCRIPT, "--site-corpus", str(corpus), "--site-name", "x",
         "--output-dir", str(tmp_path / "o")],
    )
    with pytest.raises(ValueError, match="exec events"):
        train_site_rarity.main()


def test_the_split_is_by_time_and_never_overlaps() -> None:
    from synthaea_ml.training.train_site_rarity import time_split

    train, calibration, test = time_split(100)
    assert (train.start, train.stop) == (0, 70)
    assert calibration.start == train.stop and test.start == calibration.stop
    assert test.stop == 100


def test_rarity_values_in_the_matrix_are_point_in_time(tmp_path) -> None:
    from synthaea_ml.training.train_site_rarity import build_matrices, load_corpus

    records = load_corpus(_corpus(tmp_path))
    _, x_rare, known = build_matrices(records, k=3, min_hosts=3, interval_ns=DAY)
    # The very first day has no snapshot yet: rarity is unknown there, known later.
    assert x_rare[0, 9] == 0.0 and known > 0.5
    assert set(x_rare[:, 9]) <= {0.0, 1.0} and set(x_rare[:, 10]) <= {0.0, 1.0}
