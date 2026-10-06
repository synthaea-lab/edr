"""T1 behavior-vector parity (issue #617), Python side: the dataset builder plus
`features.t1` must reproduce `fixtures/t1_golden.jsonl` from `fixtures/t1_events.jsonl`.

The Rust counterpart is `crates/ml/tests/t1_golden.rs`. If either breaks, the trainer and
the on-device scorer disagree on the 23-feature vector. Regenerate with
`fixtures/gen_t1_parity.py` only on a deliberate change.
"""

import json
from pathlib import Path

import pytest

from synthaea_ml.data.behavior_dataset import load_records
from synthaea_ml.features import t1

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def golden_rows() -> list[dict]:
    path = FIXTURES / "t1_golden.jsonl"
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


@pytest.mark.parametrize("row", golden_rows(), ids=lambda r: f"pid{r['pid']}-gen{r['process_generation']}")
def test_vectors_match_golden(row: dict) -> None:
    records = load_records(FIXTURES / "t1_events.jsonl")
    by_key = {(r["pid"], r.get("process_generation")): r for r in records}
    record = by_key[(row["pid"], row["process_generation"])]
    got = t1.extract_features(record)
    assert len(got) == len(row["features"]) == t1.FEATURE_COUNT
    for g, e in zip(got, row["features"], strict=True):
        assert g == pytest.approx(e, rel=1e-6, abs=1e-9)


def test_the_recycled_pids_second_life_does_not_inherit_the_first() -> None:
    rows = {(r["pid"], r["process_generation"]): r["features"] for r in golden_rows()}
    first, second = rows[(100, 1)], rows[(100, 2)]
    names = t1.FEATURE_NAMES
    assert first[names.index("connect_count")] == 1.0
    assert second[names.index("connect_count")] == 0.0
    assert first[names.index("parent_comm_is_webserver")] == 1.0
    assert second[names.index("parent_comm_is_webserver")] == 0.0
