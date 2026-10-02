"""The T1 behavior vector: cmdline (9) + correlation (8) + lineage (6) = 23 features.

One definition shared by the robustness evaluation, the dataset builder and the trainer
(issue #48/#617), so a model is scored on exactly the layout it was trained on. The
Rust combined scorer must build the same vector in the same order; until that exists
(it does not yet) a T1 model cannot ship, only be trained and evaluated here.

The cmdline and lineage blocks come from one exec record. The correlation block is
*context*: the eight window features of the process the exec belongs to, computed from
the event window (`records_from_events` in `synthaea_ml.data.behavior_dataset`) and
carried on the record as `correlation_features`.
"""

from __future__ import annotations

from typing import Any

from synthaea_ml.data.canonical import ml_cmdline_from_record
from synthaea_ml.features import cmdline, correlation, lineage

FEATURE_NAMES = [*cmdline.FEATURE_NAMES, *correlation.FEATURE_NAMES, *lineage.FEATURE_NAMES]
FEATURE_COUNT = len(FEATURE_NAMES)


def extract_features(record: dict[str, Any]) -> list[float]:
    """The 23-feature T1 vector for one exec record.

    A record without `correlation_features` scores as an empty window (all zeros), which
    is what a mutation test wants: the context stays fixed so a score delta can only come
    from the fields the mutator rewrote.
    """
    context = record.get("correlation_features")
    if context is None:
        context = [0.0] * len(correlation.FEATURE_NAMES)
    if len(context) != len(correlation.FEATURE_NAMES):
        raise ValueError(
            f"correlation_features must have {len(correlation.FEATURE_NAMES)} values, "
            f"got {len(context)}"
        )
    return [
        *cmdline.extract_features(ml_cmdline_from_record(record)),
        *(float(v) for v in context),
        *lineage.extract_features(record),
    ]
