# ML Engine

On-device inference tiers, feature extraction and Rust/Python parity, training pipeline,
calibration, false-positive governance. Delivery and runtime: ADR-0002 (models ship as
signed data via canary rings; inference is statically linked onnxruntime).

Beyond the mechanics, two properties are deliberate differentiators — commitments the
pipeline is built to enforce, not aspirations:

## Measured evasion cost

The project thesis — a learned model raises the cost of evasion through generalization —
is treated as a falsifiable claim, not a slogan. `synthaea_ml/evaluation/` carries an
adversarial evaluation harness: known-bad samples from lab scenarios are mutated the way
a real attacker would mutate them (cmdline re-encoding, argument reordering, path
substitution, payload chunking; timing jitter and event reordering for the behavior
tiers), and the harness reports how much perturbation is needed before the score drops
below threshold.

- Every registry entry carries a **robustness card** next to its model card: the
  mutation classes applied and the measured score degradation per class.
- Robustness regression against the previous shipped model is a **release gate**, with
  the same standing as FP governance.
- A feature that collapses under trivial mutation (e.g. a literal token list) is treated
  as a rule wearing an ML costume; the harness exists to catch exactly that.

## Per-site adaptation

Self-hosting is a modeling advantage, not just a deployment mode: each control plane
sees one fleet, so models can legitimately learn "anomalous *for this environment*"
rather than "anomalous on average". The adaptation loop is a first-class product
feature:

1. **Curate** — T3 (control plane) selects benign corpora from fleet telemetry:
   high-volume, analyst-dismissed, never-correlated activity, curated per platform.
2. **Retrain / recalibrate** — the `ml/` pipeline rebuilds T0–T2 models or their
   calibrations against the site corpus, producing a registry entry with full
   provenance (rule 3 of `ml/README.md` applies unchanged).
3. **Roll out** — canary rings ship the site model with guardrail metrics: per-ring FP
   and detection-rate telemetry, automatic halt and rollback on regression.

Constraints that keep the loop safe:

- The **global model is the floor**: a site model must meet or beat the global model on
  the shared scenario-replay suite before it ships anywhere. Adaptation may only ever
  *lower* false positives, never buy them by giving up detections — an attacker who is
  already resident must not be able to "teach" the baseline that their activity is
  normal faster than the scenario suite catches the regression.
- Curation is auditable: a site corpus is a recorded dataset version like any other, so
  a site model can be rebuilt and its training data reviewed.
- The evasion-cost harness (above) runs against site models too — both gates apply to
  every registry entry, global or per-site.

### The rarity feature (Python side, #640)

ADR-0020 (proposed) defines the fleet-derived feature a site model can use: whether the executed
image's hash is on the tenant's **common set** (seen on at least K hosts), as a small ordinal
rather than a count, because the device can only compute what a pushed snapshot lets it.
`ml/synthaea_ml/features/rarity.py` is two numbers: `rarity_known` (a snapshot exists, covers
enough hosts, and the event carries a hash; a fleet that just enrolled would otherwise look all
rare) and `image_in_common_set`.

Training it on today's counters would let the model learn from the future, so the values are
**point in time**: `synthaea_ml/data/common_set.py` replays a site corpus in time order and gives
each event the snapshot that would have been in force on the device (published every 24 h by
default; an event sees the last boundary, never anything at or after its own time). A corpus that
carries agent id, time and image hash is enough; the telemetry lake is not needed for this path.

`python -m synthaea_ml.training.train_site_rarity` trains the 9-feature cmdline baseline and the
11-feature candidate on the same **time-ordered** split (train, calibrate to the FP budget, test),
and records each model's false-positive rate on the untouched test slice in `model_record.json`.
Only the false-positive side is measured (the corpus is benign); the global-model-floor check of
`train_site_model.py` still has to pass before a site model leaves the lab.

**Not shippable:** there is no Rust mirror yet. Nothing agent-side is written until ADR-0020 is
accepted, so the agent cannot load an 11-feature model; the mirror must take the same two inputs
(a membership test and the "covers enough hosts" flag) and be pinned to the Python module by a
golden fixture.

## Scores that know when they don't know

A score is only evidence if its error rate is known. Two mechanisms, both in
`synthaea_ml/calibration/` next to the existing Bayesian LLR work:

- **Conformal thresholds.** Scorer thresholds are not conventions (`decision_function
  = 0`) but calibrated on held-out benign data to a stated false-positive budget —
  "≤ N false positives per endpoint per day under the benign distribution" is a
  property the model card states and the FP gate verifies, per platform and per tier.
- **Out-of-distribution guard.** Every scorer carries a cheap validity check: is this
  feature vector inside the region the model was trained on? An out-of-distribution
  vector produces *no score* (routed to T3 / analyst visibility as "unmodeled
  activity"), never a confidently wrong one. The correlator treats "no score" as
  absence of evidence, not as benign.

## Explanations at detection time

Every ML detection carries its explanation, computed on-device at inference time. For
tree ensembles, per-feature contribution (path attribution) is nearly free; the
detection event includes the top contributing features with their values ("entropy of
argument 3", "write burst to ~/.config", "first-seen parent→child pair"), not just a
score. Consequences:

- The **detection event schema reserves attribution fields** from the start — schema
  work, cheap now, breaking later.
- Attributions compose with the correlator's evidence into a structured case record.
  That record is what grounds the one LLM feature worth building: **server-side case
  narratives** generated from the evidence graph on the control plane. The LLM
  narrates structured evidence for the analyst; it never scores, never judges, and
  never runs on the endpoint.

## Behavior over time, not events in isolation

Snapshot scoring (one cmdline, one window of counts) is where evasion is cheapest; the
structural direction is sequence and lineage. Staged deliberately:

1. **Lineage and transition features first** — rarity of parent→child process
   transitions, ancestry-chain features, ordered event patterns per entity — feeding
   the existing tree models. No new model family, large detection gain.
2. **Fleet-informed rarity** — per-site transition frequencies computed by T3 flow
   into T0/T1 features via the per-site adaptation loop (above).
3. **Sequence models only when justified** — a small sequence model over per-entity
   event streams ships through the same pipeline with zero agent rework (ADR-0002:
   anything exportable to ONNX runs on the shipped runtime). Justified by measured
   gain on the scenario suite, not by novelty.

The rationale is the thesis itself: an attacker can rewrite any single command line
cheaply, but producing a normal-looking process lineage and event ordering is
drastically more expensive — evasion cost concentrates exactly where these features
look.

Status: design commitments recorded 2026-09-03; implementation follows the migration
order. Immediate implications: attribution fields belong in the event schema work
happening now; the adversarial harness and conformal thresholds land with
`synthaea_ml/evaluation/` and `synthaea_ml/calibration/`; the adaptation loop, fleet
rarity, and case narratives need T3 and the control plane ingest path.

## Retraining the T1 behavior model (lineage-aware)

T1 scores one process incarnation on 23 features: command line (9), correlation window
(8) and parent lineage (6). The `argv`-only baselines the T0 trainers use carry no pids,
generations or parents, so T1 trains from a **raw agent capture of normal activity**:

1. **Capture** on a real host or lab VM, with the agent writing `events.jsonl` (the
   `--events` file), while the machine does ordinary work for a representative session.
   Do not capture on WSL2: its kernel reports `ppid=0` for every event (see
   `lab/scenarios/lineage.yaml`), so the lineage block would be empty. Prefer a lab host
   from `lab/MATRIX.md`. The benign activity must include the lineage a real fleet sees
   (build tools, package managers, shells under terminals, services): an Isolation Forest
   never splits on a feature that is constant in training, so a capture where every
   parent is a system path cannot flag a suspicious parent.
2. **Write the manifest** next to it:
   `python -m synthaea_ml.data.manifest ... --baseline-filename events.jsonl`.
3. **Train**:
   `python -m synthaea_ml.training.train_behavior --dataset <dir> --output-dir ml/registry/behavior-iforest-<platform>/<version>/`
   (`--robustness-scenarios` and `--robustness-events` record the T1 robustness card, lineage
   mutators included; `--robustness-events` must be a capture of the *malicious* activity).
4. **Compare** against the baseline T1 model on the scenario suite and record detection,
   escape and false-positive rates in `model_record.json`. The release gate then holds the
   escape rate to `robustness_cli verify --max-escape-rate 0.15`.

One incarnation is one `(pid, process_generation)`: a recycled pid's earlier life never
feeds the next one's correlation counts or lineage. `tests/test_train_behavior.py` proves
the pipeline mechanically on synthetic captures and says nothing about detection quality.

**Not shippable yet:** the Rust side now has the 23-feature vector
(`ml::features::t1::extract_features(bus, pid, generation)`, pinned against Python by
`ml/tests/fixtures/t1_golden.jsonl`) and the scorer, `ml::BehaviorScorer`. The scorer loads a
T1 ONNX model with its `model_metadata.json`, applies the conformal threshold (a normal score
returns `None`) and the feature bounds (an out-of-range vector is an error, not a score), and
returns the score with its top attributions. It refuses a model that is not 23 features wide
and bounds that are not for exactly the T1 features, in order. It is pinned to onnxruntime by
`crates/ml/tests/fixtures/t1_scorer_golden.jsonl` (`gen_t1_scorer_fixture.py`, checked from
`crates/ml/tests/t1_scorer.rs`) on a small model trained on jittered synthetic vectors: that
pins Rust and Python inference, not detection quality.

Still missing: the agent does not load or run it (`agent/src/sink.rs` loads the T2 scorer only),
and there is no T1 model trained on a real capture. Until both exist a T1 model can be trained
and evaluated here but not run on-device.

**A caveat for evaluation:** an Isolation Forest ranks a value beyond the training range
no more anomalous than the range edge, so on its own it will not flag a feature value it
has never seen. That is what the shipped feature-bounds guard (`model_metadata.json`) is for;
read a T1 robustness card with that in mind.
