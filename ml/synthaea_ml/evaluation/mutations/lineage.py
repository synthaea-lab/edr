"""Lineage mutators for adversarial evaluation (issue #48, task #21).

Three mutation classes targeting parent_comm and parent_image_path fields:
- FakeParentNameMutator: replace parent with legitimate system process
- ParentPathMutator: replace parent path with system/suspicious directories
- RemoveLineageMutator: strip lineage fields (simulate sensors without parent tracking)

All mutators test robustness of lineage features against evasion attempts.
"""

import copy
from typing import Any, ClassVar

from .base import Mutator
from .prng import LCG


def _platform_of(record: dict[str, Any]) -> str | None:
    """`"windows"`, `"unix"` or `None` (cannot tell) for a record, from its paths and names.

    A Windows-style path (backslash or drive letter) or an `.exe` name means Windows; a
    rooted POSIX path means Unix. The fake-parent and parent-path mutators draw from the
    matching pool so a Linux event is never given `explorer.exe` as a parent: that
    makes the transition *rarer*, which is not a realistic evasion (#617).
    """
    hints = [
        record.get(k) for k in ("image_path", "parent_image_path", "comm", "parent_comm")
    ]
    argv = record.get("argv")
    if argv:
        hints.append(str(argv[0]))
    windows = unix = False
    for hint in hints:
        if not isinstance(hint, str) or not hint:
            continue
        if "\\" in hint or (len(hint) > 1 and hint[1] == ":") or hint.lower().endswith(".exe"):
            windows = True
        elif hint.startswith("/"):
            unix = True
    if windows and not unix:
        return "windows"
    if unix and not windows:
        return "unix"
    return None


class FakeParentNameMutator(Mutator):
    """Replace parent_comm with legitimate system process names.

    Light: Replace with common benign parent (systemd, explorer.exe)
    Medium: Replace with context-appropriate parent (shell, init process)
    Heavy: Replace with diverse legitimate names from rotating pool

    Tests if lineage features can detect anomalous parent→child transitions
    even when the parent name alone appears legitimate.
    """

    # Common legitimate parent processes across platforms
    BENIGN_PARENTS: ClassVar[list[str]] = [
        "systemd",  # Linux init (PID 1)
        "init",  # Traditional Unix init
        "launchd",  # macOS init
        "explorer.exe",  # Windows shell
        "svchost.exe",  # Windows service host
        "services.exe",  # Windows service control manager
        "System",  # Windows kernel
        "bash",  # Unix shell
        "cmd.exe",  # Windows shell
        "sshd",  # SSH daemon (common for remote shells)
    ]

    # The same pool split by platform, in the same relative order, for events whose
    # platform is known (see `_platform_of`).
    UNIX_PARENTS: ClassVar[list[str]] = ["systemd", "init", "launchd", "bash", "sshd"]
    WINDOWS_PARENTS: ClassVar[list[str]] = [
        "explorer.exe",
        "svchost.exe",
        "services.exe",
        "System",
        "cmd.exe",
    ]

    def mutation_class_name(self) -> str:
        return "fake_parent_name"

    def mutate(self, record: dict[str, Any], intensity: str, rng: LCG) -> dict[str, Any]:
        mutated = copy.deepcopy(record)

        # Only mutate if parent_comm exists (some events may lack lineage)
        if "parent_comm" not in mutated or mutated["parent_comm"] is None:
            return mutated

        platform = _platform_of(mutated)
        if intensity == "light":
            # Most common benign parent for the platform
            candidates = {
                "unix": ["systemd"],
                "windows": ["explorer.exe"],
            }.get(platform, ["systemd", "explorer.exe"])
        elif intensity == "medium":
            # Context-appropriate parents (shells, init, service managers)
            candidates = {
                "unix": self.UNIX_PARENTS[:3],
                "windows": self.WINDOWS_PARENTS[:3],
            }.get(platform, self.BENIGN_PARENTS[:5])
        elif intensity == "heavy":
            # Full pool of legitimate names for the platform
            candidates = {
                "unix": self.UNIX_PARENTS,
                "windows": self.WINDOWS_PARENTS,
            }.get(platform, self.BENIGN_PARENTS)
        else:
            raise ValueError(f"invalid intensity: {intensity}")

        # Select one at random (deterministic via rng)
        idx = rng.uniform(0, len(candidates))
        mutated["parent_comm"] = candidates[idx]

        return mutated


class ParentPathMutator(Mutator):
    """Replace parent_image_path to make the parent look more legitimate.

    Intensity is the attacker's evasion strength, as for every mutator feeding an
    *escape* metric: heavier must mean harder to detect, never easier (#617 — the first
    version had heavy pick suspicious-only paths, which only ever makes detection easier).

    Light: a mixed pool of system and suspicious paths (a weak, sometimes-useless attempt)
    Medium: system directories only, from any platform
    Heavy: system directories of the record's own platform (the most convincing)

    Tests if path-based lineage features (parent_path_is_system,
    parent_path_is_suspicious) can be evaded by moving binaries.
    """

    # Legitimate system directories
    SYSTEM_PATHS: ClassVar[list[str]] = [
        "/usr/bin/sh",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/usr/lib/systemd/systemd",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeC2RClient.exe",
    ]

    # Suspicious directories where malware often executes from
    SUSPICIOUS_PATHS: ClassVar[list[str]] = [
        "/tmp/malware",
        "/var/tmp/dropper",
        "/dev/shm/payload",
        "C:\\Users\\Public\\Downloads\\setup.exe",
        "C:\\Users\\victim\\AppData\\Local\\Temp\\evil.exe",
        "C:\\Users\\victim\\Desktop\\invoice.exe",
        "C:\\Windows\\Temp\\update.exe",
    ]

    def mutation_class_name(self) -> str:
        return "parent_path"

    def mutate(self, record: dict[str, Any], intensity: str, rng: LCG) -> dict[str, Any]:
        mutated = copy.deepcopy(record)

        # Only mutate if parent_image_path exists
        if "parent_image_path" not in mutated or mutated["parent_image_path"] is None:
            return mutated

        if intensity == "light":
            candidates = self.SYSTEM_PATHS + self.SUSPICIOUS_PATHS
        elif intensity == "medium":
            candidates = self.SYSTEM_PATHS
        elif intensity == "heavy":
            platform = _platform_of(mutated)
            candidates = {
                "unix": [p for p in self.SYSTEM_PATHS if p.startswith("/")],
                "windows": [p for p in self.SYSTEM_PATHS if not p.startswith("/")],
            }.get(platform, self.SYSTEM_PATHS)
        else:
            raise ValueError(f"invalid intensity: {intensity}")

        # Select one at random
        idx = rng.uniform(0, len(candidates))
        mutated["parent_image_path"] = candidates[idx]

        return mutated


class RemoveLineageMutator(Mutator):
    """Strip parent_comm and parent_image_path fields.

    Light: Remove parent_comm only
    Medium: Remove parent_image_path only
    Heavy: Remove both fields (full lineage strip)

    Tests model robustness when lineage information is absent. Some sensors
    don't provide parent lineage (sensor capability flag), so models must
    degrade gracefully rather than failing or producing false positives.
    """

    def mutation_class_name(self) -> str:
        return "remove_lineage"

    def mutate(self, record: dict[str, Any], intensity: str, rng: LCG) -> dict[str, Any]:
        mutated = copy.deepcopy(record)

        if intensity == "light":
            # Remove parent_comm only
            if "parent_comm" in mutated:
                mutated["parent_comm"] = None
        elif intensity == "medium":
            # Remove parent_image_path only
            if "parent_image_path" in mutated:
                mutated["parent_image_path"] = None
        elif intensity == "heavy":
            # Remove both (complete lineage strip)
            if "parent_comm" in mutated:
                mutated["parent_comm"] = None
            if "parent_image_path" in mutated:
                mutated["parent_image_path"] = None
        else:
            raise ValueError(f"invalid intensity: {intensity}")

        return mutated


# Export all T1-tier lineage mutators
ALL_LINEAGE_MUTATORS = [
    FakeParentNameMutator(),
    ParentPathMutator(),
    RemoveLineageMutator(),
]
