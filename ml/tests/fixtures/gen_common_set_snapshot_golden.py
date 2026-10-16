"""Regenerates the common-set snapshot wire-format golden file (common_set_snapshot_golden.json).

ADR-0020 ships the fleet's common set to the agent as a signed content entry. This file is the
wire format's reference, written from the spec in `docs/detection/common-set-snapshot-format.md`
with the standard library only, so it is a third implementation next to the two that must agree
with it:

  - server/tests/unit/common-set-snapshot.test.ts  (the TypeScript builder must produce these
    exact bytes)
  - crates/ml/tests/common_set_snapshot_golden.rs  (the Rust reader must parse them and answer
    membership identically)

After ANY change to the format (a version bump, per CLAUDE.md), regenerate:

    python3 ml/tests/fixtures/gen_common_set_snapshot_golden.py

Each case is `{name, params, bytes_hex, members, non_members}`. `non_members` only lists hashes
this filter answers `false` for: a Bloom filter may answer `true` for any absent hash, so the
fixture pins what is deterministic, not an absence guarantee.
"""

import hashlib
import json
import math
import struct
from pathlib import Path

MAGIC = b"SYCS"
FORMAT_VERSION = 1
HEADER_BYTES = 32
MIN_BITS = 64
MAX_HASH_COUNT = 16
MASK64 = (1 << 64) - 1


def sizing(entry_count: int, fpr: float) -> tuple[int, int]:
    """(bit_count, hash_count): the textbook Bloom sizing, bits rounded up to a whole byte."""
    if entry_count == 0:
        return MIN_BITS, 1
    bits = math.ceil(entry_count * math.log(1 / fpr) / (math.log(2) ** 2))
    bits = max(MIN_BITS, (bits + 7) // 8 * 8)
    hashes = min(MAX_HASH_COUNT, max(1, math.floor(bits / entry_count * math.log(2) + 0.5)))
    return bits, hashes


def positions(sha256_hex: str, bit_count: int, hash_count: int) -> list[int]:
    """Double hashing over the digest itself, which is already uniform: h1 and h2 are the first
    two little-endian u64 words, h2 forced odd, position_i = (h1 + i * h2) mod 2^64 mod bits."""
    raw = bytes.fromhex(sha256_hex)
    h1, h2 = struct.unpack_from("<QQ", raw, 0)
    h2 |= 1
    return [((h1 + i * h2) & MASK64) % bit_count for i in range(hash_count)]


def build(hashes: list[str], min_hosts: int, hosts_covered: int, built_at: int, fpr: float) -> bytes:
    unique = sorted(set(hashes))
    bit_count, hash_count = sizing(len(unique), fpr)
    body = bytearray(bit_count // 8)
    for h in unique:
        for p in positions(h, bit_count, hash_count):
            body[p >> 3] |= 1 << (p & 7)
    header = MAGIC + struct.pack(
        "<HHIIIIQ", FORMAT_VERSION, hash_count, min_hosts, hosts_covered, len(unique), bit_count, built_at
    )
    assert len(header) == HEADER_BYTES
    return header + bytes(body)


def contains(blob: bytes, sha256_hex: str) -> bool:
    _, hash_count, _, _, _, bit_count, _ = struct.unpack_from("<HHIIIIQ", blob, 4)
    return all(blob[HEADER_BYTES + (p >> 3)] >> (p & 7) & 1 for p in positions(sha256_hex, bit_count, hash_count))


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


# (name, member count, min_hosts, hosts_covered, built_at, fpr)
CASES = [
    ("empty_set", 0, 3, 0, 0, 0.01),
    ("one_hash", 1, 3, 4, 1_791_849_600, 0.01),
    ("fifty_hashes_one_percent", 50, 3, 12, 1_791_849_600, 0.01),
    ("two_hundred_hashes_one_in_a_thousand", 200, 5, 40, 1_791_936_000, 0.001),
]


def main() -> None:
    cases = []
    for name, n, min_hosts, covered, built_at, fpr in CASES:
        members = [digest(f"{name}-member-{i}") for i in range(n)]
        blob = build(members, min_hosts, covered, built_at, fpr)
        absent = [h for h in (digest(f"{name}-other-{i}") for i in range(400)) if not contains(blob, h)][:20]
        cases.append(
            {
                "name": name,
                "params": {
                    "min_hosts": min_hosts,
                    "hosts_covered": covered,
                    "built_at": built_at,
                    "false_positive_rate": fpr,
                    "hashes": members,
                },
                "bytes_hex": blob.hex(),
                "members": members[:20],
                "non_members": absent,
            }
        )
    out = Path(__file__).with_name("common_set_snapshot_golden.json")
    out.write_text(json.dumps({"format_version": FORMAT_VERSION, "cases": cases}, indent=1) + "\n")
    print(f"wrote {out} ({len(cases)} cases)")


if __name__ == "__main__":
    main()
