"""A shipped model (`model.onnx` and `model_metadata.json`) seen as the estimator the evaluation
code expects: a `decision_function`, and the conformal threshold the agent's scorer would use.

The training scripts keep the fitted scikit-learn estimator in hand; a floor check against the
global model has only what ships, so it scores through `onnxruntime`, as the agent does.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort

MODEL_FILENAME = "model.onnx"
METADATA_FILENAME = "model_metadata.json"
SCORES_OUTPUT = "scores"


class ShippedModel:
    """`decision_function` over an ONNX isolation forest, plus its `threshold`.

    `threshold_source` says where the threshold came from, so a record can tell a calibrated one
    from the default."""

    def __init__(self, model_bytes: bytes, threshold: float, threshold_source: str) -> None:
        self._session = ort.InferenceSession(model_bytes, providers=["CPUExecutionProvider"])
        self._input = self._session.get_inputs()[0]
        self.n_features_in_ = int(self._input.shape[1])
        self.threshold = threshold
        self.threshold_source = threshold_source

    def decision_function(self, x: Any) -> np.ndarray:
        rows = np.asarray(x, dtype=np.float32)
        if rows.ndim != 2 or rows.shape[1] != self.n_features_in_:
            raise ValueError(
                f"the model takes {self.n_features_in_} features, got rows of shape {rows.shape}"
            )
        scores = self._session.run([SCORES_OUTPUT], {self._input.name: rows})[0]
        return np.asarray(scores, dtype=np.float64).reshape(-1)


def load_shipped_model(directory: Path) -> ShippedModel:
    """Loads `model.onnx` and, when there is one, the threshold of `model_metadata.json`.

    Without metadata the threshold is 0, as in the agent's scorer (`crates/ml/src/scorer.rs`:
    "models without metadata still work (no OOD validation, threshold defaults to 0)"); metadata
    that carries no threshold is refused rather than read as that default."""
    directory = Path(directory)
    model_path = directory / MODEL_FILENAME
    if not model_path.is_file():
        raise FileNotFoundError(f"no {MODEL_FILENAME} in {directory}")
    metadata_path = directory / METADATA_FILENAME
    if metadata_path.is_file():
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if "threshold" not in metadata:
            raise ValueError(f"{metadata_path} has no threshold")
        threshold, source = float(metadata["threshold"]), METADATA_FILENAME
    else:
        threshold, source = 0.0, f"no {METADATA_FILENAME}, so the agent's default of 0"
    return ShippedModel(model_path.read_bytes(), threshold, source)
