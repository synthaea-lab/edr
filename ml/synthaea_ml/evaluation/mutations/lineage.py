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

    def mutation_class_name(self) -> str:
        return "fake_parent_name"

    def mutate(self, record: dict[str, Any], intensity: str, rng: LCG) -> dict[str, Any]:
        mutated = copy.deepcopy(record)

        # Only mutate if parent_comm exists (some events may lack lineage)
        if "parent_comm" not in mutated or mutated["parent_comm"] is None:
            return mutated

        if intensity == "light":
            # Most common benign parent (systemd on Linux, explorer.exe on Windows)
            candidates = ["systemd", "explorer.exe"]
        elif intensity == "medium":
            # Context-appropriate parents (shells, init, service managers)
            candidates = self.BENIGN_PARENTS[:5]
        elif intensity == "heavy":
            # Full pool of legitimate names
            candidates = self.BENIGN_PARENTS
        else:
            raise ValueError(f"invalid intensity: {intensity}")

        # Select one at random (deterministic via rng)
        idx = rng.uniform(0, len(candidates))
        mutated["parent_comm"] = candidates[idx]

        return mutated


class ParentPathMutator(Mutator):
    """Replace parent_image_path with legitimate or suspicious directory paths.

    Light: Replace with system directory (makes parent appear legitimate)
    Medium: Replace with mixed system/suspicious paths
    Heavy: Replace with suspicious paths (temp, downloads, appdata)

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
            # System directories only (make parent look legitimate)
            candidates = self.SYSTEM_PATHS
        elif intensity == "medium":
            # Mixed system and suspicious paths
            candidates = self.SYSTEM_PATHS + self.SUSPICIOUS_PATHS
        elif intensity == "heavy":
            # Suspicious paths only (test if detector relies on path alone)
            candidates = self.SUSPICIOUS_PATHS
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
