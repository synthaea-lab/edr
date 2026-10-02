"""Extraction of the "multi-events per pid" feature vector, for a second ML scorer — a
complement to the cmdline vector (`features.py`), never merged with it into a single model
(decision of 2026-08-27, see docs/design/design-correlation-ml-vector.md).

**Must stay in sync with the Rust mirror** (crates/synthaea-ml/src/correlation_features.rs):
exact same definitions, same output order.

Expected input format: a list of JSON-Lines events, one object per event, as produced by
`edr-cli capture-events` / `edr-cli run` in `events.jsonl`:
    {"type": "exec",     "pid": 1234, "ts_ns": 1000000000, "comm": "curl", "cmdline": "..."}
    {"type": "connect",  "pid": 1234, "ts_ns": 2000000000, "daddr_v4": [127,0,0,1],
                         "dport": 4444, "is_ipv6": false}
    {"type": "fileopen", "pid": 1234, "ts_ns": 3000000000, "path": "...", "flags": 65}
    {"type": "network_flow", "pid": 1234, "ts_ns": 4000000000, "daddr_v4": [10,0,0,1],
                         "dport": 9999}

`network_flow` (netlink-observed, ADR-0008) is absorbed into the same `unique_daddr_count`/
`unique_dport_count` sets as `connect` — see `extract_features` below. `connect_count` stays
`connect`-only.

`flags` is logged raw; the filtering on write intent (access mode `O_WRONLY`/`O_RDWR`,
or `O_CREAT`) happens here, exactly mirroring `schema::has_write_intent` on the Rust side
(`features/behavior.py` applies the same test).
"""

# ── Rust mirror constants (POSIX flags) ───────────────────────────────────────

O_ACCMODE = 0o3
O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100

FEATURE_NAMES = [
    "spawn_count",
    "connect_count",
    "filewrite_count",
    "unique_daddr_count",
    "unique_dport_count",
    "has_full_chain",
    "span_s",
    "event_count",
]


def _is_file_write(event: dict) -> bool:
    """Mirror of `schema::has_write_intent` (Rust, the ONE definition): a `fileopen`
    whose access mode is `O_WRONLY`/`O_RDWR`, or that carries `O_CREAT`. The access
    mode is a 2-bit *field* (`O_ACCMODE`), not independent bits — the invalid `0o3`
    combination is refused by the kernel (`EINVAL`), so it does not count as a write
    (this replaced a drifted bitmask test that disagreed with the Rust rules engine)."""
    if event.get("type") != "fileopen":
        return False
    flags = int(event.get("flags", 0))
    access_mode = flags & O_ACCMODE
    return access_mode in (O_WRONLY, O_RDWR) or bool(flags & O_CREAT)


def same_generation(recorded: int | None, wanted: int | None) -> bool:
    """Whether an event stamped `recorded` can belong to the process incarnation `wanted`.

    Mirror of `correlator::bus::same_generation`: two known, different stamps are two
    incarnations of a recycled pid and never mix; a missing stamp on either side cannot
    disprove identity, which keeps stamp-less captures behaving exactly as before.
    """
    return recorded is None or wanted is None or recorded == wanted


def events_for_pid(events: list[dict], pid: int, generation: int | None = None) -> list[dict]:
    """The events of one process incarnation: Python mirror of `EventBus::events_for_pid`.

    Records carry the stamp under `process_generation` (the `EventMeta` field name).
    """
    return [
        e
        for e in events
        if e["pid"] == pid and same_generation(e.get("process_generation"), generation)
    ]


def extract_features(
    events: list[dict], pid: int, generation: int | None = None
) -> list[float]:
    """`events`: all events of a correlation window (not only those of the requested pid —
    the pid filtering happens here, like `EventBus::events_for_pid` on the Rust side).

    `generation` is the process incarnation (#590): a recycled pid's earlier life must not
    feed this one's features. `None` keeps the pid-only behavior."""
    pid_events = events_for_pid(events, pid, generation)

    spawn_count = sum(1 for e in pid_events if e["type"] == "exec")
    connect_count = sum(1 for e in pid_events if e["type"] == "connect")
    filewrite_count = sum(1 for e in pid_events if _is_file_write(e))

    # ADR-0008: Connect and NetworkFlow (netlink) are absorbed into the same
    # daddr/dport sets — one count of "distinct destinations touched" regardless of
    # which sensor captured them. connect_count above stays Connect-only.
    daddrs = {
        tuple(e["daddr_v4"]) for e in pid_events if e["type"] in ("connect", "network_flow")
    }
    dports = {e["dport"] for e in pid_events if e["type"] in ("connect", "network_flow")}

    has_full_chain = (
        1.0 if (spawn_count >= 1 and connect_count >= 1 and filewrite_count >= 1) else 0.0
    )

    if pid_events:
        span_s = (
            max(e["ts_ns"] for e in pid_events) - min(e["ts_ns"] for e in pid_events)
        ) / 1_000_000_000.0
    else:
        span_s = 0.0

    return [
        float(spawn_count),
        float(connect_count),
        float(filewrite_count),
        float(len(daddrs)),
        float(len(dports)),
        has_full_chain,
        span_s,
        float(len(pid_events)),
    ]


# ── Parity with the Rust tests (crates/synthaea-ml/src/correlation_features.rs) ──

if __name__ == "__main__":
    print("=== Tests correlation_features.py (mirror of the Rust tests) ===\n")

    # vecteur_vide_pour_pid_absent
    assert extract_features([], 1234) == [0.0] * 8
    assert extract_features([{"type": "exec", "pid": 1, "ts_ns": 0}], 1234) == [0.0] * 8
    print("[OK] absent pid → zero vector")

    # chaine_complete_a_has_full_chain_a_un
    evs = [
        {"type": "exec", "pid": 99, "ts_ns": 0},
        {
            "type": "connect",
            "pid": 99,
            "ts_ns": 1_000_000_000,
            "daddr_v4": [127, 0, 0, 1],
            "dport": 4444,
        },
        {"type": "fileopen", "pid": 99, "ts_ns": 2_000_000_000, "flags": O_WRONLY | O_CREAT},
    ]
    f = extract_features(evs, 99)
    assert f[0] == 1.0 and f[1] == 1.0 and f[2] == 1.0, f
    assert f[5] == 1.0, "has_full_chain"
    assert f[6] == 2.0, "span_s 0->2s"
    assert f[7] == 3.0, "event_count"
    print(f"[OK] full chain: {f}")

    # spawn_seul_n_a_pas_has_full_chain
    assert extract_features([{"type": "exec", "pid": 1, "ts_ns": 0}], 1)[5] == 0.0
    print("[OK] spawn alone → has_full_chain=0")

    # a read-only fileopen does not count as a filewrite
    ro = [{"type": "fileopen", "pid": 5, "ts_ns": 0, "flags": 0}]  # O_RDONLY
    assert extract_features(ro, 5)[2] == 0.0, "read-only ≠ filewrite"
    print("[OK] fileopen O_RDONLY → filewrite_count=0")

    # destinations_multiples_comptees_une_fois_chacune
    net = [
        {"type": "connect", "pid": 7, "ts_ns": 0, "daddr_v4": [127, 0, 0, 1], "dport": 4444},
        {
            "type": "connect",
            "pid": 7,
            "ts_ns": 1_000_000_000,
            "daddr_v4": [127, 0, 0, 1],
            "dport": 4444,
        },
        {
            "type": "connect",
            "pid": 7,
            "ts_ns": 2_000_000_000,
            "daddr_v4": [127, 0, 0, 1],
            "dport": 8080,
        },
    ]
    fn = extract_features(net, 7)
    assert fn[1] == 3.0, "connect_count"
    assert fn[3] == 1.0, "unique_daddr_count"
    assert fn[4] == 2.0, "unique_dport_count"
    print(f"[OK] distinct destinations: {fn}")

    # network_flow_absorbe_dans_les_memes_sets_daddr_dport_que_connect (ADR-0008)
    mixte = [
        {
            "type": "connect",
            "pid": 7,
            "ts_ns": 0,
            "daddr_v4": [127, 0, 0, 1],
            "dport": 4444,
        },
        {
            "type": "network_flow",
            "pid": 7,
            "ts_ns": 1_000_000_000,
            "daddr_v4": [10, 0, 0, 1],
            "dport": 4444,
        },
        {
            "type": "network_flow",
            "pid": 7,
            "ts_ns": 2_000_000_000,
            "daddr_v4": [10, 0, 0, 2],
            "dport": 9999,
        },
    ]
    fm = extract_features(mixte, 7)
    assert fm[3] == 3.0, "unique_daddr_count spans connect + network_flow"
    assert fm[4] == 2.0, "unique_dport_count spans connect + network_flow"
    assert fm[7] == 3.0, "event_count includes network_flow"
    print(f"[OK] network_flow absorbed into connect's daddr/dport sets: {fm}")

    # pids_differents_isoles
    mix = [
        {"type": "exec", "pid": 1, "ts_ns": 0},
        {
            "type": "connect",
            "pid": 2,
            "ts_ns": 1_000_000_000,
            "daddr_v4": [1, 1, 1, 1],
            "dport": 4444,
        },
    ]
    assert extract_features(mix, 1)[1] == 0.0
    assert extract_features(mix, 2)[0] == 0.0
    print("[OK] isolated pids")

    print("\nAll tests pass.")
