"""The per-site recalibration entry point (#49) runs end to end.

`train_site_model.main` passed a manifest *file* to `dataset_version_from_manifest` (which
takes the baseline directory) and called `write_training_record(output_dir=...)` (the
parameter is `model_dir`), so every real run died with an exception after training and
exporting. Nothing exercised it, so the loop #49 was closed on could not complete.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from synthaea_ml.registry.training_record import load_training_record
from synthaea_ml.training import train_site_model
from tests.test_trainers import _LINUX_SAMPLES, _write_baseline_dir


def test_the_site_trainer_completes_and_records_both_datasets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    global_dir = tmp_path / "linux__dev__abc__2026-09-11"
    _write_baseline_dir(global_dir, _LINUX_SAMPLES, platform="linux", workload="dev")
    corpus = tmp_path / "corpus-v1.jsonl"
    corpus.write_text(
        "\n".join(
            json.dumps(
                {
                    "timestamp": "2026-09-23T10:00:00Z",
                    "event_type": "exec",
                    "agent_id": "a1",
                    "event": {"argv": ["/opt/site/tool", f"--job{i}"]},
                }
            )
            for i in range(8)
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "site-model"
    monkeypatch.setattr(
        "sys.argv",
        [
            train_site_model.TRAINING_SCRIPT,
            "--global-dataset",
            str(global_dir),
            "--site-corpus",
            str(corpus),
            "--output-dir",
            str(out),
            "--site-name",
            "acme",
        ],
    )
    train_site_model.main()

    assert (out / "model.onnx").exists()
    record = load_training_record(out)
    assert [d.name for d in record.dataset_versions][-1] == "site-corpus-acme"
    assert len(record.dataset_versions) == 2
