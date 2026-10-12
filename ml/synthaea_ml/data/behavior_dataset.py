"""Builds the T1 training set from a raw agent capture (issue #617).

Input: the agent's own `events.jsonl` (`crates/schema::Event` JSON: identity nested under
`meta`, lineage beside the command line), captured over a normal-activity session. Output:
one exec record per **process incarnation** `(pid, process_generation)`, carrying the
command line, the parent lineage and `correlation_features`: the eight window features of
that process, computed over `[last_ts - window, last_ts]` exactly like
`aggregate_correlation.vecteurs_par_pid` (the 2026-09-02 "most complete instant for a PID"
decision) and filtered by incarnation like `EventBus::events_for_pid` (#590), so a recycled
pid's earlier life never feeds the next one.

A process with no exec in the capture has no command line and no lineage to score, so it
yields no record.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from synthaea_ml.data.aggregate_correlation import RAW_EVENT_TYPES, flatten_wire_event
from synthaea_ml.features import correlation

DEFAULT_WINDOW_NS = 60 * 1_000_000_000


def load_events(path: Path) -> list[dict[str, Any]]:
    """The usable events of a capture, flattened (see `flatten_wire_event`).

    Unreadable lines and event types the correlation features do not use are skipped.
    """
    if not path.exists():
        raise FileNotFoundError(f"capture not found: {path}")
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(raw, dict) and raw.get("type") in RAW_EVENT_TYPES:
            flat = flatten_wire_event(raw)
            if flat is not None:
                events.append(flat)
    return events


def records_from_events(
    events: list[dict[str, Any]],
    window_ns: int = DEFAULT_WINDOW_NS,
    min_events: int = 1,
) -> list[dict[str, Any]]:
    """One exec record per process incarnation, with its correlation context.

    Args:
        events: Flattened events (`load_events`).
        window_ns: Correlation window ending at the incarnation's last event.
        min_events: Skip an incarnation with fewer events than this in its window.
    """
    incarnations: dict[tuple[int, int | None], list[dict[str, Any]]] = {}
    for event in events:
        incarnations.setdefault((event["pid"], event.get("process_generation")), []).append(event)

    # The correlation features of a process only read that pid's events (`events_for_pid`), so
    # the window is taken from the pid's own events instead of scanning the whole capture for
    # every incarnation: a real capture has a million events and thousands of incarnations,
    # which the full scan made quadratic (hours on a 30-minute capture).
    by_pid: dict[int, list[dict[str, Any]]] = {}
    for event in events:
        by_pid.setdefault(event["pid"], []).append(event)

    records: list[dict[str, Any]] = []
    for (pid, generation), own in sorted(
        incarnations.items(), key=lambda kv: (kv[0][0], kv[0][1] is None, kv[0][1] or 0)
    ):
        execs = [e for e in own if e["type"] == "exec"]
        if not execs:
            continue
        last_ts = max(e["ts_ns"] for e in own)
        cutoff = last_ts - window_ns
        window = [e for e in by_pid[pid] if e["ts_ns"] >= cutoff]
        features = correlation.extract_features(window, pid, generation)
        if features[-1] < min_events:  # event_count is the last correlation feature
            continue
        exec_event = max(execs, key=lambda e: e["ts_ns"])
        record = {k: v for k, v in exec_event.items() if k not in ("type", "ts_ns")}
        record["correlation_features"] = features
        records.append(record)
    return records


def load_records(
    path: Path, window_ns: int = DEFAULT_WINDOW_NS, min_events: int = 1
) -> list[dict[str, Any]]:
    """`records_from_events(load_events(path))`."""
    return records_from_events(load_events(path), window_ns, min_events)
