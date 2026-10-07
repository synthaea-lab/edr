"""Regenerates the T1 behavior-scorer parity fixture (issue #617):

    crates/ml/tests/fixtures/t1_scorer.onnx           (a small 23-feature IsolationForest)
    crates/ml/tests/fixtures/t1_scorer_golden.jsonl   ({pid, process_generation, score})

The inference-path counterpart of `gen_t1_parity.py`: that pins the 23-feature *vector*,
this pins the *score* `ml::BehaviorScorer` (Rust vector from an `EventBus`, then `ort`)
computes against the one onnxruntime computes from the Python vector of the same
incarnations. It reuses `t1_events.jsonl` / `t1_golden.jsonl`, so run `gen_t1_parity.py`
first if those change.

The model is trained on jittered copies of the benign incarnations of that capture. It
exists to pin Rust == Python inference, not detection quality; a model trained on a real
capture is what #617 is waiting for. `score` is null for an incarnation with no exec in the
window (the scorer returns `None` and the model is never asked).

Run from `ml/tests/fixtures/` with a venv holding numpy, scikit-learn, skl2onnx, onnx,
onnxruntime:

    python3 gen_t1_scorer_fixture.py

Regenerate only on a deliberate change to the T1 layout or the model recipe, never to
paper over a red parity test.
"""

import json
from pathlib import Path

import numpy as np
import onnxruntime
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE.parents[2] / "crates" / "ml" / "tests" / "fixtures"

golden = [json.loads(line) for line in (HERE / "t1_golden.jsonl").read_text().splitlines() if line]
rows = {(r["pid"], r["process_generation"]): np.array(r["features"], dtype=np.float32) for r in golden}

# Benign incarnations: no web-server or Office parent, nothing downloaded and dropped.
BENIGN = [(100, 2), (200, None), (300, None)]
rng = np.random.default_rng(617)
base = np.stack([rows[k] for k in BENIGN])
train_x = np.repeat(base, 150, axis=0)
train_x = train_x + rng.normal(0.0, 0.05, train_x.shape).astype(np.float32) * (train_x != 0)
train_x = train_x.astype(np.float32)

model = IsolationForest(n_estimators=20, max_samples=64, contamination=0.02, random_state=42)
model.fit(train_x)

onnx_model = to_onnx(model, train_x, target_opset={"ai.onnx.ml": 3, "": 18})
model_path = OUT_DIR / "t1_scorer.onnx"
model_path.write_bytes(onnx_model.SerializeToString())

sess = onnxruntime.InferenceSession(model_path.read_bytes(), providers=["CPUExecutionProvider"])
lines = []
for (pid, generation), vec in rows.items():
    x = vec.reshape(1, -1)
    score = float(sess.run(["scores"], {"X": x})[0].reshape(-1)[0])
    lines.append({"pid": pid, "process_generation": generation, "score": score})
# An incarnation with no exec in the window: not scored.
lines.append({"pid": 9999, "process_generation": None, "score": None})

xs = np.stack(list(rows.values()))
skl = model.decision_function(xs)
ort_scores = sess.run(["scores"], {"X": xs})[0].reshape(-1)
assert np.allclose(skl, ort_scores, atol=1e-5), f"onnx vs sklearn diverge:\n{skl=}\n{ort_scores=}"

(OUT_DIR / "t1_scorer_golden.jsonl").write_text("".join(json.dumps(r) + "\n" for r in lines))
print(f"wrote {model_path.name} ({model_path.stat().st_size} bytes) and t1_scorer_golden.jsonl")
for r in lines:
    print(f"  pid={r['pid']:<5} gen={r['process_generation']!s:<5} score={r['score']}")
