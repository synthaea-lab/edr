"""Tests for `synthaea_ml.data.manifest` — the baseline dataset manifest sidecar.

The manifest is what mechanically enforces rule 3 of `ml/README.md` (a registry
model records the exact dataset versions it was trained on), so these tests
lock the properties the rest of the ML space will assume:

- The host hash is stable across captures on the same machine, distinct across
  different machines, and cannot be reconstructed from an empty hostname.
- Writing then reading a manifest is a round-trip.
- `verify_manifest` catches the "someone edited the baseline without
  regenerating the manifest" case, which would otherwise silently produce a
  model card that names a dataset version it was not trained on.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from synthaea_ml.data.manifest import (
    MANIFEST_FILENAME,
    SCHEMA_VERSION,
    hash_hostname,
    load_manifest,
    verify_manifest,
    write_manifest,
)

_START = datetime(2026, 9, 11, 10, 0, 0, tzinfo=UTC)
_END = datetime(2026, 9, 11, 11, 0, 0, tzinfo=UTC)


def _write_baseline(dir_path: Path, lines: list[str], name: str = "baseline.jsonl") -> Path:
    path = dir_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# --- hash_hostname ----------------------------------------------------------


def test_hash_hostname_is_stable_for_same_input() -> None:
    assert hash_hostname("solkapc") == hash_hostname("solkapc")


def test_hash_hostname_differs_across_hostnames() -> None:
    assert hash_hostname("solkapc") != hash_hostname("hugopc")


def test_hash_hostname_is_12_hex_chars() -> None:
    h = hash_hostname("solkapc")
    assert len(h) == 12
    assert all(c in "0123456789abcdef" for c in h)


def test_hash_hostname_empty_raises() -> None:
    with pytest.raises(ValueError):
        hash_hostname("")


# --- write_manifest / load_manifest round-trip -----------------------------


def test_write_manifest_round_trip(tmp_path: Path) -> None:
    _write_baseline(tmp_path, ['{"argv": ["ls", "-la"]}', '{"argv": ["whoami"]}'])

    written = write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
        capturer_ref="solkapc-run-1",
    )
    loaded = load_manifest(tmp_path)

    assert loaded == written
    assert loaded.schema_version == SCHEMA_VERSION
    assert loaded.host_id == hash_hostname("solkapc")
    assert loaded.platform == "linux"
    assert loaded.workload_label == "dev"
    assert loaded.capture_start == "2026-09-11T10:00:00Z"
    assert loaded.capture_end == "2026-09-11T11:00:00Z"
    assert loaded.sample_count == 2
    assert loaded.capturer_ref == "solkapc-run-1"


def test_manifest_json_is_sorted_and_indented(tmp_path: Path) -> None:
    """The on-disk JSON must be diffable — sorted keys, indent=2. Anyone who
    inspects a manifest sidecar in a review needs the diff to be readable."""
    _write_baseline(tmp_path, ['{"argv": ["ls"]}'])
    write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
    )

    raw = (tmp_path / MANIFEST_FILENAME).read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert list(parsed.keys()) == sorted(parsed.keys())
    assert "\n  " in raw  # indent=2 present


def test_write_manifest_skips_blank_lines_in_sample_count(tmp_path: Path) -> None:
    _write_baseline(
        tmp_path,
        ['{"argv": ["ls"]}', "", '{"argv": ["whoami"]}', "  ", '{"argv": ["id"]}'],
    )
    m = write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
    )
    assert m.sample_count == 3


def test_write_manifest_uses_socket_hostname_when_not_provided(tmp_path: Path) -> None:
    """We only assert the hash format — the socket hostname of the test host
    is not something we want to hard-code."""
    _write_baseline(tmp_path, ['{"argv": ["ls"]}'])
    m = write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
    )
    assert len(m.host_id) == 12


def test_write_manifest_accepts_extra_field(tmp_path: Path) -> None:
    _write_baseline(tmp_path, ['{"argv": ["ls"]}'])
    m = write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
        extra={"hypervisor": "hyperv", "iteration": "3"},
    )
    loaded = load_manifest(tmp_path)
    assert loaded.extra == {"hypervisor": "hyperv", "iteration": "3"}
    assert m.extra == loaded.extra


def test_write_manifest_missing_baseline_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        write_manifest(
            tmp_path,
            platform="linux",
            os_version="22.04",
            workload_label="dev",
            capture_start=_START,
            capture_end=_END,
            hostname="solkapc",
        )


def test_write_manifest_naive_datetime_raises(tmp_path: Path) -> None:
    _write_baseline(tmp_path, ['{"argv": ["ls"]}'])
    naive = datetime(2026, 9, 11, 10, 0, 0)  # noqa: DTZ001 — no tzinfo, must be rejected
    with pytest.raises(ValueError):
        write_manifest(
            tmp_path,
            platform="linux",
            os_version="22.04",
            workload_label="dev",
            capture_start=naive,
            capture_end=_END,
            hostname="solkapc",
        )


def test_write_manifest_converts_non_utc_to_utc(tmp_path: Path) -> None:
    """A capture_start in a non-UTC zone is normalised to the same UTC instant.
    This is the property that makes cross-timezone captures comparable."""
    paris_offset = timezone(timedelta(hours=2))
    _write_baseline(tmp_path, ['{"argv": ["ls"]}'])
    start_paris = datetime(2026, 9, 11, 12, 0, 0, tzinfo=paris_offset)
    m = write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=start_paris,
        capture_end=_END,
        hostname="solkapc",
    )
    assert m.capture_start == "2026-09-11T10:00:00Z"


def test_write_manifest_custom_baseline_filename(tmp_path: Path) -> None:
    _write_baseline(
        tmp_path,
        ['{"argv": ["ls"]}', '{"argv": ["whoami"]}'],
        name="baseline_capture.jsonl",
    )
    m = write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
        baseline_filename="baseline_capture.jsonl",
    )
    assert m.sample_count == 2


# --- load_manifest ---------------------------------------------------------


def test_load_manifest_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_manifest(tmp_path)


def test_load_manifest_unsupported_schema_version_raises(tmp_path: Path) -> None:
    """A schema version this reader does not know is a hard fail — bump-only-on-break
    means an unknown version means an unknown format."""
    (tmp_path / MANIFEST_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION + 42,
                "host_id": "abc123abc123",
                "platform": "linux",
                "os_version": "22.04",
                "workload_label": "dev",
                "capture_start": "2026-09-11T10:00:00Z",
                "capture_end": "2026-09-11T11:00:00Z",
                "sample_count": 1,
                "sample_sha256": "0" * 64,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported manifest schema_version"):
        load_manifest(tmp_path)


# --- verify_manifest -------------------------------------------------------


def test_verify_manifest_matches_after_write(tmp_path: Path) -> None:
    _write_baseline(tmp_path, ['{"argv": ["ls"]}', '{"argv": ["whoami"]}'])
    write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
    )
    # No exception — the manifest we just wrote must verify.
    verify_manifest(tmp_path)


def test_verify_manifest_detects_edited_baseline(tmp_path: Path) -> None:
    """The exact case this whole module exists to prevent — a baseline edited
    (or truncated, or appended-to) after the manifest was written."""
    baseline = _write_baseline(tmp_path, ['{"argv": ["ls"]}', '{"argv": ["whoami"]}'])
    write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
    )
    # Append a new sample — the hash no longer matches.
    with baseline.open("a", encoding="utf-8") as f:
        f.write('{"argv": ["id"]}\n')

    with pytest.raises(ValueError, match="baseline hash mismatch"):
        verify_manifest(tmp_path)


def test_verify_manifest_accepts_legacy_baseline_filename(tmp_path: Path) -> None:
    """A manifest written for a legacy file name (kept as-is rather than renamed
    to `baseline.jsonl`) must verify against that same name, not the default."""
    lines = ['{"argv": ["ls"]}', '{"argv": ["whoami"]}']
    _write_baseline(tmp_path, lines, name="baseline_benign.jsonl")
    write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
        baseline_filename="baseline_benign.jsonl",
    )
    # No exception — matching the write_manifest call above, not the default.
    verify_manifest(tmp_path, baseline_filename="baseline_benign.jsonl")


def test_verify_manifest_wrong_filename_reports_the_missing_file(tmp_path: Path) -> None:
    _write_baseline(tmp_path, ['{"argv": ["ls"]}'], name="baseline_benign.jsonl")
    write_manifest(
        tmp_path,
        platform="linux",
        os_version="22.04",
        workload_label="dev",
        capture_start=_START,
        capture_end=_END,
        hostname="solkapc",
        baseline_filename="baseline_benign.jsonl",
    )
    with pytest.raises(FileNotFoundError, match="baseline.jsonl"):
        verify_manifest(tmp_path)
