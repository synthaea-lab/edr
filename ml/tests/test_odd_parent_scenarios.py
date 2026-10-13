"""The odd-parent capture scenarios must say what makes their parent odd, and must be odd only
that way (#617, the review of #787).

The T1 lineage features read the parent's name (`parent_comm_is_*`) and its path
(`parent_path_is_suspicious`: `/tmp/`, `/var/tmp/`, `/dev/shm/`, ...). A scenario that runs a
web-server-named parent from `/var/tmp` is odd by both, so a gain measured on it cannot be
credited to either. Each scenario therefore declares `# Odd by: comm` or `# Odd by: path`, and
the ones odd by comm may not touch a suspicious directory.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from synthaea_ml.features.lineage import SUSPICIOUS_PATHS

SCENARIOS = sorted(
    (Path(__file__).resolve().parents[2] / "lab" / "ml-capture" / "odd-parents").glob("*.sh")
)
UNIX_SUSPICIOUS = [p for p in SUSPICIOUS_PATHS if p.startswith("/")]


def declared_kind(text: str) -> str | None:
    match = re.search(r"^# Odd by: (comm|path)\b", text, re.MULTILINE)
    return match.group(1) if match else None


def code_lines(text: str) -> list[str]:
    """The script without its comment lines: a header may talk about /var/tmp."""
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def test_the_odd_parent_scenarios_exist() -> None:
    assert len(SCENARIOS) >= 3, SCENARIOS


@pytest.mark.parametrize("script", SCENARIOS, ids=lambda p: p.name)
def test_each_scenario_declares_what_makes_its_parent_odd(script: Path) -> None:
    assert declared_kind(script.read_text(encoding="utf-8")) is not None, (
        f"{script.name} needs a `# Odd by: comm` or `# Odd by: path` header line"
    )


@pytest.mark.parametrize("script", SCENARIOS, ids=lambda p: p.name)
def test_a_scenario_odd_by_comm_runs_from_a_neutral_directory(script: Path) -> None:
    text = script.read_text(encoding="utf-8")
    if declared_kind(text) != "comm":
        pytest.skip("odd by path")
    code = "\n".join(code_lines(text))
    used = [p for p in UNIX_SUSPICIOUS if p in code]
    assert not used, f"{script.name} is odd by comm but runs from {used}: path and comm are confounded"
    assert "$HOME" in code, f"{script.name} should work under the user's own directory"


@pytest.mark.parametrize("script", SCENARIOS, ids=lambda p: p.name)
def test_a_scenario_odd_by_path_really_runs_from_a_suspicious_directory(script: Path) -> None:
    text = script.read_text(encoding="utf-8")
    if declared_kind(text) != "path":
        pytest.skip("odd by comm")
    code = "\n".join(code_lines(text))
    assert any(p in code for p in UNIX_SUSPICIOUS), f"{script.name} claims a suspicious path but uses none"


def test_a_scenario_odd_by_path_does_not_borrow_a_name_the_comm_features_know() -> None:
    """Its binaries must not be named like a web server or an office application, or the
    comm features would fire too and the two causes would be confounded again."""
    from synthaea_ml.features.lineage import OFFICE_COMMS, WEBSERVER_COMMS

    for script in SCENARIOS:
        text = script.read_text(encoding="utf-8")
        if declared_kind(text) != "path":
            continue
        code = "\n".join(code_lines(text))
        for name in [*WEBSERVER_COMMS, *OFFICE_COMMS]:
            assert not re.search(rf"[/\"' ]{re.escape(name)}[\"' ]", code), (script.name, name)


def test_the_malicious_runner_runs_every_odd_parent_scenario() -> None:
    runner = (SCENARIOS[0].parents[1] / "malicious-run.sh").read_text(encoding="utf-8")
    for script in SCENARIOS:
        assert f"odd-parents/{script.stem}" in runner, script.name
