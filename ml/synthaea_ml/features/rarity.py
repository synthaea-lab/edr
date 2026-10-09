"""The rarity feature: is the executed image on this fleet's common set? (issue #640)

Defined by ADR-0020 (accepted): the server publishes, per tenant, a **common-set snapshot**
of the image hashes seen on at least K hosts, and the device checks an executed image
against it locally. The model input is therefore a small ordinal derived from that
snapshot, never a host count: a count is not something the device can compute.

Two numbers, because "rare" must be distinguishable from "no basis to say":

- `rarity_known`: 1.0 when a snapshot exists, covers enough hosts to mean anything and the
  event carries an image hash; otherwise 0.0. A fleet that just enrolled has an empty
  snapshot, and without this every binary on it would look rare (ADR-0020 withholds the
  evidence until the snapshot covers a stated number of hosts).
- `image_in_common_set`: 1.0 when known and the hash is in the common set, else 0.0. Only
  meaningful when `rarity_known` is 1.0; 0.0 there means "rare or new on this fleet".

**Python side only for now.** The Rust mirror is not written yet (ADR-0020 is accepted), so a model trained on this feature cannot be loaded by
the agent yet. When it is built it must take the same two inputs (a membership test and
the "covers enough hosts" flag) and be pinned to this module by a golden fixture, like
every other feature.
"""

from __future__ import annotations

from dataclasses import dataclass

FEATURE_NAMES = ["rarity_known", "image_in_common_set"]

_HEX = set("0123456789abcdef")


def normalize_sha256(value: object) -> str | None:
    """The key the server's counters use: 64 lowercase hex characters, else `None`."""
    if not isinstance(value, str):
        return None
    lowered = value.strip().lower()
    return lowered if len(lowered) == 64 and set(lowered) <= _HEX else None


@dataclass(frozen=True)
class CommonSetSnapshot:
    """One published snapshot: the hashes seen on at least K hosts, and how many hosts the
    fleet had reported when it was taken."""

    common: frozenset[str]
    hosts_covered: int

    def covers(self, min_hosts: int) -> bool:
        return self.hosts_covered >= min_hosts


def extract_features(
    sha256: object, snapshot: CommonSetSnapshot | None, min_hosts: int
) -> list[float]:
    """The two rarity features for one executed image against the snapshot in force."""
    key = normalize_sha256(sha256)
    if key is None or snapshot is None or not snapshot.covers(min_hosts):
        return [0.0, 0.0]
    return [1.0, 1.0 if key in snapshot.common else 0.0]
