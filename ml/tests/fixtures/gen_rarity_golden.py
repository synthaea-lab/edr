"""Regenerates the Python/Rust rarity-feature parity golden file (fixtures/rarity_golden.jsonl).

The golden file locks the rarity feature (ADR-0020, #640): `synthaea_ml.features.rarity` (training,
Python) and `ml::features::rarity` (inference, Rust) MUST produce the same two numbers for the
same hash, snapshot and minimum coverage. Both test suites consume it:

  - ml/tests/test_rarity_golden.py          (pytest: drift on the Python side)
  - crates/ml/tests/rarity_golden.rs        (cargo test: drift on the Rust side)

Python is the reference. After ANY change to rarity.py, regenerate and retrain:

    python tests/fixtures/gen_rarity_golden.py

Each row is `{name, sha256, snapshot, min_hosts, features}` where `snapshot` is `null` or
`{"common": [...], "hosts_covered": n}`.
"""

import json
from pathlib import Path

from synthaea_ml.features.rarity import CommonSetSnapshot, extract_features

H1 = "a" * 64
H2 = "b" * 64
MIXED = "0123456789abcdef" * 4


def snap(common: list[str], hosts: int) -> dict:
    return {"common": common, "hosts_covered": hosts}


# (name, sha256, snapshot, min_hosts)
CASES: list[tuple[str, str | None, dict | None, int]] = [
    ("known_and_common", H1, snap([H1, H2], 10), 5),
    ("known_and_rare", H2, snap([H1], 10), 5),
    ("mixed_digits_and_letters_common", MIXED, snap([MIXED], 5), 5),
    ("coverage_exactly_at_the_minimum", H1, snap([H1], 5), 5),
    ("coverage_one_below_the_minimum", H1, snap([H1], 4), 5),
    ("zero_minimum_with_an_empty_snapshot_still_knows", H1, snap([], 0), 0),
    ("empty_snapshot_below_the_minimum", H1, snap([], 0), 3),
    ("huge_coverage", H2, snap([H1], 10**12), 5),
    ("no_snapshot", H1, None, 5),
    ("no_hash", None, snap([H1], 10), 5),
    ("empty_hash", "", snap([H1], 10), 5),
    ("uppercase_hash_is_normalized", H1.upper(), snap([H1], 10), 5),
    ("mixed_case_hash_is_normalized", MIXED[:32].upper() + MIXED[32:], snap([MIXED], 10), 5),
    ("space_padded", f"  {H1}  ", snap([H1], 10), 5),
    ("newline_and_tab_padded", f"\t{H1}\n", snap([H1], 10), 5),
    ("no_break_space_padded", f" {H1} ", snap([H1], 10), 5),
    ("ideographic_space_padded", f"　{H1}　", snap([H1], 10), 5),
    ("ascii_separator_padded", f"\x1c{H1}\x1f", snap([H1], 10), 5),
    ("one_character_short", H1[:63], snap([H1], 10), 5),
    ("one_character_long", H1 + "a", snap([H1], 10), 5),
    ("non_hex_character", "g" + H1[1:], snap([H1], 10), 5),
    ("fullwidth_digits_are_not_hex", "１" * 64, snap([H1], 10), 5),
    ("inner_space", H1[:32] + " " + H1[33:], snap([H1], 10), 5),
    ("a_common_set_entry_that_is_not_normalized_never_matches", H1, snap([H1.upper()], 10), 5),
    ("a_padded_hash_is_looked_up_normalized", f" {H2} ", snap([H1, H2], 10), 5),
]


def main() -> None:
    out = Path(__file__).resolve().parent / "rarity_golden.jsonl"
    with out.open("w", encoding="utf-8", newline="\n") as f:
        for name, sha256, snapshot, min_hosts in CASES:
            parsed = (
                None
                if snapshot is None
                else CommonSetSnapshot(frozenset(snapshot["common"]), snapshot["hosts_covered"])
            )
            features = extract_features(sha256, parsed, min_hosts)
            row = {
                "name": name,
                "sha256": sha256,
                "snapshot": snapshot,
                "min_hosts": min_hosts,
                "features": features,
            }
            f.write(json.dumps(row) + "\n")
    print(f"wrote {out} ({len(CASES)} cases)")


if __name__ == "__main__":
    main()
