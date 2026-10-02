"""Test suite for combined correlation + lineage features."""

import pytest

from synthaea_ml.features import combined, correlation, lineage


def test_combined_feature_count():
    """Combined features should have 14 features (8 correlation + 6 lineage)."""
    assert len(combined.FEATURE_NAMES) == 14
    assert len(combined.FEATURE_NAMES) == len(correlation.FEATURE_NAMES) + len(lineage.FEATURE_NAMES)


def test_combined_feature_names():
    """Feature names should be ordered: correlation first, then lineage."""
    expected = correlation.FEATURE_NAMES + lineage.FEATURE_NAMES
    assert combined.FEATURE_NAMES == expected


def test_extract_combined_features_empty_events():
    """Extract features from empty event list."""
    features = combined.extract_combined_features([], 1234)
    assert len(features) == 14
    assert all(f == 0.0 for f in features)


def test_extract_combined_features_no_lineage():
    """Extract features when no exec event (no lineage info)."""
    events = [
        {"type": "connect", "pid": 1000, "ts_ns": 1_000_000_000, "daddr_v4": [127, 0, 0, 1], "dport": 8080},
    ]
    features = combined.extract_combined_features(events, 1000)

    assert len(features) == 14
    # Correlation features should be populated
    assert features[1] == 1.0  # connect_count
    # Lineage features should be 0 (no exec event)
    assert all(f == 0.0 for f in features[8:])  # lineage features all 0


def test_extract_combined_features_with_lineage():
    """Extract features with both correlation and lineage."""
    events = [
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
            "daddr_v4": [192, 168, 1, 1],
            "dport": 4444,
        },
    ]

    features = combined.extract_combined_features(events, 1001)

    assert len(features) == 14
    # Correlation features
    assert features[0] == 1.0  # spawn_count
    assert features[1] == 1.0  # connect_count
    assert features[7] == 2.0  # event_count

    # Lineage features
    assert features[8] == 1.0   # has_parent_lineage
    assert features[9] == 0.0   # parent_comm_is_shell
    assert features[10] == 1.0  # parent_comm_is_webserver (nginx)
    assert features[12] == 1.0  # parent_path_is_system (/usr/sbin/)


def test_extract_combined_features_dict():
    """Extract features as named dict."""
    events = [
        {
            "type": "exec",
            "pid": 1002,
            "ts_ns": 1_000_000_000,
            "image_path": "C:\\Windows\\System32\\cmd.exe",
            "cmdline": "cmd.exe",
            "parent_comm": "winword.exe",
            "parent_image_path": "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
        },
    ]

    features_dict = combined.extract_combined_features_dict(events, 1002)

    assert len(features_dict) == 14
    assert features_dict["spawn_count"] == 1.0
    assert features_dict["has_parent_lineage"] == 1.0
    assert features_dict["parent_comm_is_office"] == 1.0
    assert features_dict["parent_path_is_system"] == 1.0


@pytest.mark.parametrize(
    "sample_name",
    list(combined.SANITY_CHECK_SAMPLES.keys()),
    ids=list(combined.SANITY_CHECK_SAMPLES.keys()),
)
def test_sanity_check_samples(sample_name):
    """All sanity check samples should extract without error."""
    sample = combined.SANITY_CHECK_SAMPLES[sample_name]
    features = combined.extract_combined_features(sample["events"], sample["pid"])
    assert len(features) == 14
    assert all(isinstance(f, float) for f in features)


def test_webshell_pattern_detection():
    """Webshell attack should have distinctive feature signature."""
    sample = combined.SANITY_CHECK_SAMPLES["webshell_attack"]
    features_dict = combined.extract_combined_features_dict(
        sample["events"], sample["pid"]
    )

    # Should have correlation activity
    assert features_dict["connect_count"] >= 1.0
    assert features_dict["filewrite_count"] >= 2.0
    assert features_dict["has_full_chain"] == 1.0

    # Should have webserver parent
    assert features_dict["has_parent_lineage"] == 1.0
    assert features_dict["parent_comm_is_webserver"] == 1.0
    assert features_dict["parent_comm_is_shell"] == 0.0


def test_malicious_macro_pattern_detection():
    """Malicious macro should have distinctive feature signature."""
    sample = combined.SANITY_CHECK_SAMPLES["malicious_macro"]
    features_dict = combined.extract_combined_features_dict(
        sample["events"], sample["pid"]
    )

    # Should have suspicious correlation activity
    assert features_dict["spawn_count"] >= 2.0
    assert features_dict["connect_count"] >= 3.0
    assert features_dict["has_full_chain"] == 1.0

    # Most recent exec should have office parent (winword.exe)
    assert features_dict["has_parent_lineage"] == 1.0
    # Note: Most recent exec is powershell with parent cmd.exe, not winword
    # The lineage extraction uses most recent exec event


def test_dropper_pattern_detection():
    """Dropper from suspicious path should have distinctive signature."""
    sample = combined.SANITY_CHECK_SAMPLES["dropper_from_tmp"]
    features_dict = combined.extract_combined_features_dict(
        sample["events"], sample["pid"]
    )

    # Should have high correlation activity
    assert features_dict["spawn_count"] >= 3.0
    assert features_dict["connect_count"] >= 5.0

    # Most recent exec should have bash parent
    assert features_dict["has_parent_lineage"] == 1.0
    assert features_dict["parent_comm_is_shell"] == 1.0  # bash parent


def test_pid_isolation():
    """Events from different PIDs should not interfere."""
    events = [
        {"type": "exec", "pid": 100, "ts_ns": 0, "image_path": "/bin/ls", "cmdline": "ls"},
        {"type": "connect", "pid": 200, "ts_ns": 1_000_000_000, "daddr_v4": [1, 1, 1, 1], "dport": 80},
    ]

    features_100 = combined.extract_combined_features(events, 100)
    features_200 = combined.extract_combined_features(events, 200)

    # PID 100 should have spawn but no connect
    assert features_100[0] == 1.0  # spawn_count
    assert features_100[1] == 0.0  # connect_count

    # PID 200 should have connect but no spawn
    assert features_200[0] == 0.0  # spawn_count
    assert features_200[1] == 1.0  # connect_count


# --- #617: (pid, generation) filtering, mirroring `EventBus::events_for_pid` (#590) ---


def _two_lives():
    """One pid, two incarnations: the first connected out, the second only execs."""
    return [
        {"type": "exec", "pid": 9, "process_generation": 1, "ts_ns": 1_000_000_000,
         "image_path": "/bin/sh", "cmdline": "sh", "parent_comm": "nginx",
         "parent_image_path": "/usr/sbin/nginx"},
        {"type": "connect", "pid": 9, "process_generation": 1, "ts_ns": 2_000_000_000,
         "daddr_v4": [10, 0, 0, 1], "dport": 4444},
        {"type": "exec", "pid": 9, "process_generation": 2, "ts_ns": 5_000_000_000,
         "image_path": "/bin/ls", "cmdline": "ls", "parent_comm": "bash",
         "parent_image_path": "/bin/bash"},
    ]


def test_a_recycled_pids_earlier_life_feeds_neither_correlation_nor_lineage():
    names = combined.FEATURE_NAMES
    second = dict(zip(names, combined.extract_combined_features(_two_lives(), 9, 2), strict=True))
    assert second["connect_count"] == 0.0, "the first life's connect must not leak"
    assert second["spawn_count"] == 1.0
    # Lineage is the second life's parent (bash), not the most recent exec of the pid
    # overall by accident of ordering and not the first life's nginx.
    assert second["parent_comm_is_shell"] == 1.0
    assert second["parent_comm_is_webserver"] == 0.0

    first = dict(zip(names, combined.extract_combined_features(_two_lives(), 9, 1), strict=True))
    assert first["connect_count"] == 1.0
    assert first["parent_comm_is_webserver"] == 1.0


def test_no_generation_keeps_the_pid_only_behavior():
    """`None` on either side cannot disprove identity: stamp-less captures and the golden
    fixtures behave exactly as before."""
    features = dict(
        zip(combined.FEATURE_NAMES, combined.extract_combined_features(_two_lives(), 9), strict=True)
    )
    assert features["spawn_count"] == 2.0
    assert features["connect_count"] == 1.0
    unstamped = [{k: v for k, v in e.items() if k != "process_generation"} for e in _two_lives()]
    assert combined.extract_combined_features(unstamped, 9, 2) == combined.extract_combined_features(
        unstamped, 9
    )


def test_same_generation_matches_the_rust_rule():
    assert correlation.same_generation(None, None)
    assert correlation.same_generation(None, 3)
    assert correlation.same_generation(3, None)
    assert correlation.same_generation(3, 3)
    assert not correlation.same_generation(3, 4)
