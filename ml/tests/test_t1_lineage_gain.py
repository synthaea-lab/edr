"""The lineage-gain measurement (issue #617).

Synthetic vectors and wire events only: they pin the arithmetic (what counts as detected,
what the gain is, which processes are the scenario's) and that the tool refuses data too thin
to say anything. They say nothing about detection on a real host.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from synthaea_ml.evaluation import t1_lineage_gain as gain
from synthaea_ml.features import t1

S = 1_000_000_000
LINEAGE_COLUMNS = slice(gain.BASELINE_FEATURE_COUNT, t1.FEATURE_COUNT)


# has_parent, parent_is_shell, parent_is_webserver, parent_is_office, parent_in_system_path,
# parent_in_suspicious_path: the ordinary parents of a normal session. They must vary: an
# Isolation Forest never splits on a feature that is constant in training, so a benign set with
# one lineage could not teach it that another is odd (the reason #617 needs a varied capture).
BENIGN_LINEAGES = np.array(
    [
        [1, 1, 0, 0, 1, 0],  # a shell in /usr/bin
        [1, 0, 0, 0, 1, 0],  # systemd or sshd in /usr
        [1, 1, 0, 0, 0, 0],  # a shell from an unlisted path (a user-installed shell)
        [0, 0, 0, 0, 0, 0],  # no parent known
        [1, 0, 1, 0, 1, 0],  # a web server worker in /usr running a helper
        [1, 1, 0, 0, 0, 1],  # a user's script under /tmp (a build, a test run)
    ],
    dtype=float,
)
BENIGN_LINEAGE_WEIGHTS = [0.35, 0.25, 0.1, 0.1, 0.1, 0.1]


def _benign(rng: np.random.Generator, n: int) -> np.ndarray:
    """Varied benign vectors: noisy cmdline and context, one of the ordinary lineages."""
    matrix = rng.normal(loc=5.0, scale=1.0, size=(n, t1.FEATURE_COUNT))
    matrix[:, LINEAGE_COLUMNS] = BENIGN_LINEAGES[
        rng.choice(len(BENIGN_LINEAGES), size=n, p=BENIGN_LINEAGE_WEIGHTS)
    ]
    return matrix.astype(np.float32)


def _malicious_with_odd_lineage(rng: np.random.Generator, n: int) -> np.ndarray:
    """The same command-line behaviour as the benign set, from a web server running in /tmp.

    Each of its lineage values occurs in the benign set; only the combination is new.
    """
    matrix = _benign(rng, n)
    matrix[:, LINEAGE_COLUMNS] = np.array([1, 0, 1, 0, 0, 1], dtype=float)
    return matrix


def test_a_malicious_run_that_differs_only_in_its_lineage_is_gained_by_the_lineage_features() -> (
    None
):
    rng = np.random.default_rng(0)
    report = gain.measure_gain(_benign(rng, 400), _malicious_with_odd_lineage(rng, 40), seeds=8)

    assert report.with_lineage.auc_mean > 0.9
    assert report.without_lineage.auc_mean < 0.65, "17 features cannot see a lineage-only attack"
    assert report.auc_gain_mean > 0.25
    assert report.seeds_where_lineage_is_not_worse == 8


def test_a_lineage_the_benign_capture_never_varied_is_invisible_to_the_model() -> None:
    """Why #617 needs a benign capture with varied parents: an Isolation Forest never splits on
    a feature that is constant in training, so it cannot learn that another value is odd."""
    rng = np.random.default_rng(6)
    benign = _benign(rng, 400)
    benign[:, LINEAGE_COLUMNS] = BENIGN_LINEAGES[0]  # one lineage only, as a thin capture has

    report = gain.measure_gain(benign, _malicious_with_odd_lineage(rng, 40), seeds=8)

    assert report.with_lineage.auc_mean < 0.65
    assert abs(report.auc_gain_mean) < 0.1


def test_a_malicious_run_that_differs_only_in_its_command_line_gains_nothing_from_the_lineage() -> (
    None
):
    rng = np.random.default_rng(1)
    malicious = _benign(rng, 40)
    malicious[:, : gain.BASELINE_FEATURE_COUNT] += 12.0  # cmdline and context far out of range

    report = gain.measure_gain(_benign(rng, 400), malicious, seeds=8)

    assert report.without_lineage.auc_mean > 0.95
    assert abs(report.auc_gain_mean) < 0.05


def test_the_baseline_is_the_vector_without_its_lineage_block() -> None:
    assert gain.BASELINE_FEATURE_COUNT == 17
    assert t1.FEATURE_NAMES[gain.BASELINE_FEATURE_COUNT :][0] == "has_parent_lineage"


def test_a_benign_set_too_small_to_split_is_refused() -> None:
    rng = np.random.default_rng(2)
    with pytest.raises(ValueError, match="distinct benign vectors"):
        gain.measure_gain(_benign(rng, 10), _malicious_with_odd_lineage(rng, 5), seeds=2)


def test_identical_benign_vectors_count_once() -> None:
    rng = np.random.default_rng(3)
    one = _benign(rng, 1)
    with pytest.raises(ValueError, match="1 distinct benign vectors"):
        gain.measure_gain(np.repeat(one, 500, axis=0), _malicious_with_odd_lineage(rng, 5), seeds=2)


def test_no_malicious_vector_is_refused_not_reported_as_zero_detection() -> None:
    rng = np.random.default_rng(4)
    with pytest.raises(ValueError, match="no malicious"):
        gain.measure_gain(_benign(rng, 100), np.empty((0, t1.FEATURE_COUNT)), seeds=2)


def test_a_matrix_of_the_wrong_width_is_refused() -> None:
    rng = np.random.default_rng(5)
    with pytest.raises(ValueError, match="23 columns"):
        gain.measure_gain(_benign(rng, 100)[:, :17], _malicious_with_odd_lineage(rng, 5), seeds=2)


# ── Which processes are the scenario's ──────────────────────────────────────────────


def _event(kind: str, pid: int, ppid: int, ts: int, gen: int, parent_gen: int, **extra) -> dict:
    meta = {
        "pid": pid,
        "ppid": ppid,
        "timestamp_ns": ts,
        "comm": "x",
        "process_generation": gen,
        "parent_process_generation": parent_gen,
    }
    return {"type": kind, "meta": meta, **extra}


def _capture(tmp_path: Path, events: list[dict]) -> Path:
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    return path


def test_the_scenarios_tree_includes_a_child_that_never_exec_d_but_not_a_bystander(
    tmp_path: Path,
) -> None:
    events = [
        _event("exec", 100, 1, 10 * S, 1, 0, argv=["bash"]),  # the runner
        _event("file_open", 101, 100, 11 * S, 2, 1, path="/tmp/x", flags=0),  # a subshell
        _event("exec", 102, 101, 12 * S, 3, 2, argv=["nc"]),  # its child, through the subshell
        _event("exec", 200, 1, 12 * S, 4, 0, argv=["cron"]),  # a bystander in the window
    ]
    members = gain.descendants_of(_capture(tmp_path, events), 100, 5 * S, 20 * S)
    assert members == {(100, 1), (101, 2), (102, 3)}


def test_a_recycled_pid_outside_the_window_is_not_the_runner(tmp_path: Path) -> None:
    events = [
        _event("exec", 100, 1, 1 * S, 1, 0, argv=["old"]),  # the pid's earlier life
        _event("exec", 100, 1, 30 * S, 9, 0, argv=["runner"]),
        _event("exec", 150, 100, 31 * S, 10, 9, argv=["child"]),
        _event("exec", 160, 100, 99 * S, 11, 1, argv=["child-of-the-old-life"]),
    ]
    members = gain.descendants_of(_capture(tmp_path, events), 100, 25 * S, 40 * S)
    assert (100, 1) not in members
    assert (150, 10) in members
    assert (160, 11) not in members


def test_the_malicious_matrix_leaves_the_runner_itself_out(tmp_path: Path) -> None:
    events = [
        _event(
            "exec",
            100,
            1,
            10 * S,
            1,
            0,
            argv=["bash", "run.sh"],
            parent_comm="sshd",
            parent_image_path="/usr/sbin/sshd",
            image_path="/usr/bin/bash",
        ),
        _event(
            "exec",
            102,
            100,
            12 * S,
            3,
            1,
            argv=["nc", "-l", "4444"],
            parent_comm="bash",
            parent_image_path="/tmp/mybash",
            image_path="/usr/bin/nc",
        ),
    ]
    matrix = gain.malicious_matrix(_capture(tmp_path, events), 100, 5 * S, 20 * S)
    assert matrix.shape == (1, t1.FEATURE_COUNT)
