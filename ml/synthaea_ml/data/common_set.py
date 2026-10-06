"""Point-in-time common-set snapshots from a site corpus (issue #640).

Training the rarity feature on today's counters would let the model learn from the future
(a hash that only became common after the event looks common to it). ADR-0020 therefore
requires the value *as of the event*. The server cannot supply that: its counters are not
rebuilt from history, and the lake that would hold snapshot history does not exist. A site
corpus (`{timestamp, event_type, event, agent_id}` per line, exported by
`/api/corpus/finalize`) carries enough to reconstruct it by itself: when each host
executed each image hash.

`point_in_time_snapshots` replays the corpus in time order and, for every record, returns
the snapshot that would have been in force on the device at that moment: the server
publishes a snapshot every `interval_ns`, so an event sees the snapshot taken at the most
recent boundary, not the live state. Nothing at or after the event's own time contributes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from synthaea_ml.features.rarity import CommonSetSnapshot, normalize_sha256

DEFAULT_K = 3
"""Hosts an image must have run on to be in the common set (ADR-0020's K)."""

DEFAULT_INTERVAL_NS = 24 * 3600 * 1_000_000_000
"""Cadence of published snapshots: daily, riding the content manifest (ADR-0016)."""


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _timestamp_ns(record: dict[str, Any]) -> int:
    """Nanoseconds since the epoch, in integer arithmetic (a float would round at this
    scale). The export writes UTC (`...Z`); a zone-less stamp is read as UTC too."""
    stamp = datetime.fromisoformat(record["timestamp"])
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return (stamp - _EPOCH) // timedelta(microseconds=1) * 1000


def _executed_hash(record: dict[str, Any]) -> str | None:
    if record.get("event_type") != "exec":
        return None
    event = record.get("event")
    return normalize_sha256(event.get("sha256")) if isinstance(event, dict) else None


def point_in_time_snapshots(
    records: list[dict[str, Any]],
    k: int = DEFAULT_K,
    interval_ns: int = DEFAULT_INTERVAL_NS,
) -> list[CommonSetSnapshot | None]:
    """The snapshot in force for each record, aligned with `records` (input order is free).

    `None` until the first boundary has passed: a fleet has no snapshot before the server
    has published one. A host counts once per hash however often it ran it, and a record
    without an agent id or a valid hash adds no host (it still gets a snapshot, so the
    caller can score it as "no hash").
    """
    if k < 1 or interval_ns < 1:
        raise ValueError("k and interval_ns must be at least 1")
    order = sorted(range(len(records)), key=lambda i: (_timestamp_ns(records[i]), i))
    result: list[CommonSetSnapshot | None] = [None] * len(records)
    hosts_by_hash: dict[str, set[str]] = {}
    reporting: set[str] = set()
    frozen: CommonSetSnapshot | None = None
    next_boundary: int | None = None

    for i in order:
        ts = _timestamp_ns(records[i])
        if next_boundary is None:
            next_boundary = ts + interval_ns
        if ts >= next_boundary:
            # Freeze the state as it was before this event, then skip every boundary the
            # event's time has already passed (a quiet stretch publishes the same state).
            frozen = CommonSetSnapshot(
                common=frozenset(h for h, hosts in hosts_by_hash.items() if len(hosts) >= k),
                hosts_covered=len(reporting),
            )
            next_boundary += ((ts - next_boundary) // interval_ns + 1) * interval_ns
        result[i] = frozen
        agent = records[i].get("agent_id")
        if isinstance(agent, str) and agent:
            reporting.add(agent)
            digest = _executed_hash(records[i])
            if digest is not None:
                hosts_by_hash.setdefault(digest, set()).add(agent)
    return result
