"""Golden parity test: rarity.py must reproduce fixtures/rarity_golden.jsonl exactly.

The Rust counterpart (crates/ml/tests/rarity_golden.rs) consumes the same file: if either of
the two tests breaks, one implementation has drifted from the other and a model trained on
the rarity feature would be scored on vectors it never saw (ADR-0020, #640).
"""

import json
from pathlib import Path

import pytest

from synthaea_ml.features.rarity import FEATURE_NAMES, CommonSetSnapshot, extract_features

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "rarity_golden.jsonl"


def golden_rows() -> list[dict]:
    with GOLDEN.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def snapshot_of(row: dict) -> CommonSetSnapshot | None:
    raw = row["snapshot"]
    if raw is None:
        return None
    return CommonSetSnapshot(frozenset(raw["common"]), raw["hosts_covered"])


@pytest.mark.parametrize("row", golden_rows(), ids=lambda r: r["name"])
def test_features_match_golden(row: dict) -> None:
    got = extract_features(row["sha256"], snapshot_of(row), row["min_hosts"])
    assert len(got) == len(row["features"]) == len(FEATURE_NAMES)
    assert got == row["features"], (
        f"rarity drifted for {row['name']!r}: {got} != {row['features']} -- "
        "check ml/tests/fixtures/rarity_golden.jsonl"
    )


def test_golden_covers_both_features_and_both_zero_causes() -> None:
    """Every column and every way to be 0.0 must be pinned, or the file locks nothing."""
    rows = golden_rows()
    assert any(r["features"] == [1.0, 1.0] for r in rows), "no known-and-common case"
    assert any(r["features"] == [1.0, 0.0] for r in rows), "no known-and-rare case"
    assert any(r["features"] == [0.0, 0.0] and r["snapshot"] is None for r in rows)
    assert any(
        r["features"] == [0.0, 0.0]
        and r["snapshot"] is not None
        and r["snapshot"]["hosts_covered"] < r["min_hosts"]
        for r in rows
    ), "no case where the snapshot covers too few hosts"
    assert any(r["features"] == [0.0, 0.0] and r["sha256"] is None for r in rows)


def test_golden_is_what_the_generator_writes() -> None:
    """The committed file is regenerated, not hand-edited: a stale one fails here."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_rarity_golden", GOLDEN.with_name("gen_rarity_golden.py")
    )
    assert spec is not None and spec.loader is not None
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    expected = []
    for name, sha256, snapshot, min_hosts in gen.CASES:
        parsed = (
            None
            if snapshot is None
            else CommonSetSnapshot(frozenset(snapshot["common"]), snapshot["hosts_covered"])
        )
        expected.append(
            {
                "name": name,
                "sha256": sha256,
                "snapshot": snapshot,
                "min_hosts": min_hosts,
                "features": extract_features(sha256, parsed, min_hosts),
            }
        )
    assert golden_rows() == expected
