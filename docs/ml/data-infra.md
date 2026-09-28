# ML Data Infrastructure

The scaffolding that makes rule 3 of `ml/README.md` — **reproducibility** — enforceable
at ship time, and gives rule 2 — **no model ships without an evaluation record** — the
provenance half of that record. Three artifacts, one verification path: a registry
model can be rebuilt from its recorded dataset versions and config, and `verify_onnx`
refuses to accept anything else.

Introduced by the #44 stack: PR #170 (dataset manifest), PR #174 (training entry
points refactor), PR #177 (training record), PR #180 (release gate hook in
`verify_onnx`), PR #187 (CLI wrapper for the manifest), PR #192 (first real baseline
through the pipeline), PR #194 (`verify_manifest` accepts non-default baseline
filenames for legacy captures).

## Overview

Three artifacts, one loop:

| Artifact | Path | Answers |
| --- | --- | --- |
| Dataset manifest | `datasets/baselines/<slug>/manifest.json` | What is this baseline made of, and who captured it? |
| Training record | `registry/<model>/<version>/training.json` | What did this model consume, and how was it built? |
| Release gate | `python -m synthaea_ml.export.verify_onnx` | Does the shipped model still match what was recorded? |

The manifest and the training record are the ground truth. The release gate is the
audit: given a model on disk, it walks the record back to the manifests it references
and refuses to sign off if anything drifted. Under `SYNTHAEA_STRICT_PROVENANCE=1` a
missing training record is a hard failure; in dev mode it is a warning.

## Dataset manifest

A manifest pins one baseline capture at one point in time. It sits in the same
directory as its `baseline.jsonl`, is committed to the repo, and is the source of
truth every training run cites when it consumes that baseline.

`synthaea_ml/data/manifest.py` — the `Manifest` dataclass plus `write_manifest`,
`load_manifest`, `verify_manifest`. Fields on disk:

| Field | Meaning |
| --- | --- |
| `schema_version` | Bumped only on breaking readers; currently `1` |
| `platform` | `linux`, `windows`, `macos` — the OS the capture came from |
| `os_version` | Free-form kernel or OS build string (traceability, not parsing) |
| `host_id` | `sha256(hostname)[:12]` — 48 bits, enough to identify hosts across a fleet without exposing the hostname |
| `capturer_ref` | Free-form ref for human tracing (a commit, a ticket, an operator name) |
| `workload_label` | Bin the capture role: `desktop-user`, `dev`, `admin`, `server-idle` |
| `capture_start`, `capture_end` | UTC ISO-8601 window the capture spans |
| `sample_count` | Number of records in the sample file |
| `sample_sha256` | SHA-256 of the sample file — the version's identity |

`verify_manifest(baseline_dir, baseline_filename="baseline.jsonl")` re-reads the
sample file, recomputes the hash and count, and refuses if either drifts. That is
what pins a baseline against accidental edits: a stray `sed -i` on a `.jsonl` will
be caught by the next `verify_onnx` on any model that trained on it. The
`baseline_filename` keyword (#194) is what lets a manifest also cover a legacy
capture whose sample file kept its original name (`baseline_benign.jsonl`) instead
of the canonical `baseline.jsonl`.

The **directory name on disk is a rangement label, not a schema field** — the vast
majority of tooling reads the manifest, not the folder name. Three baselines
currently live under `datasets/baselines/`: two legacy ones from before this
infrastructure (`linux-wsl2-solkapc-2026-09-09` and `windows-solkapc-2026-09-08`,
both with `baseline_benign.jsonl` and no manifest yet), and one canonical example
produced through the full pipeline (`linux-wsl2-solkapc-2026-09-09-v2` — 423
cmdlines, `baseline.jsonl` + `manifest.json`, see #192).

## Training record

A training record pins one model to the exact baselines and config that produced it.
It sits next to `model.onnx`, is written by the trainer at export time, and is what
the release gate consumes.

`synthaea_ml/registry/training_record.py` — the `TrainingRecord` and
`DatasetVersion` dataclasses plus `dataset_version_from_manifest`,
`write_training_record`, `load_training_record`. Fields on disk:

| Field | Meaning |
| --- | --- |
| `schema_version` | Currently `1` |
| `trained_at` | UTC RFC-3339 timestamp of the run |
| `training_script` | Path-like ref (`synthaea_ml/training/train_linux.py`) — traceability, not resolved |
| `dataset_versions` | List of `DatasetVersion` — one per baseline consumed |
| `hyperparameters` | Round-tripped dict; not interpreted (`{"contamination": 0.05, "n_estimators": 100, ...}`) |
| `extra` | Optional `{str: str}` for anything a run wants to annotate without a typed field |

Each `DatasetVersion` in that list has three fields:

| Field | Meaning |
| --- | --- |
| `name` | Canonical dataset id — `default_dataset_name(baseline_dir)` builds it as `<platform>__<workload_label>__<host_id>__<YYYY-MM-DD>` |
| `baseline_sha256` | The manifest's `sample_sha256` at record time — locked |
| `sample_count` | Cheap cross-check before the slower hash comparison |

`verify_training_record(model_dir, baselines_root)` walks each entry back to
`baselines_root/<any dir whose manifest matches>`, re-verifies the manifest, and
asserts the recorded `baseline_sha256` still matches. Any mismatch raises
`ValueError`.

`dataset_version_from_manifest(baseline_dir)` is the intended constructor: it
verifies the manifest **before** returning the `DatasetVersion`, so a caller
building a training record cannot accidentally bake in an already-drifted hash.

## Release gate

`synthaea_ml/export/verify_onnx.py` runs before a model ships. It has always
checked runtime properties of the ONNX artifact — `scores` output present,
finite, deterministic, label/score sign agreement. As of PR #180 it also
checks provenance:

```
verify_provenance(model_dir, baselines_root, *, strict) -> None
```

- Reads `model_dir/training.json`.
- If absent — pre-#44 legacy entry, no provenance to check — **warn** in dev
  mode, **fail** under `SYNTHAEA_STRICT_PROVENANCE=1`.
- If present — call `verify_training_record`. Any mismatch is a
  `VerificationError` and `verify_onnx` exits non-zero.

The env var lets local dev on legacy entries not be a papercut while CI
enforces the strict form. When the two legacy entries are retrained through
the new pipeline, the env var can be flipped to default-strict and eventually
retired.

## Pipeline end-to-end

```
┌──────────────┐   ┌───────────────┐   ┌────────────────┐   ┌───────────────┐
│  agent       │──▶│ capture_to_   │──▶│ baseline.jsonl │──▶│ manifest.json │
│  capture     │   │ baseline.py   │   │                │   │ (manifest     │
│              │   │               │   │                │   │  write CLI)   │
└──────────────┘   └───────────────┘   └────────────────┘   └───────┬───────┘
                                                                    │
                                       ┌────────────────────────────┘
                                       │  dataset_version_from_manifest
                                       ▼  (re-verifies manifest first)
                             ┌──────────────────┐   ┌───────────────┐   ┌──────────────┐
                             │ train_{linux,    │──▶│ model.onnx    │──▶│ training.    │
                             │  windows}.py     │   │               │   │ json         │
                             │ --dataset D1 D2  │   └───────┬───────┘   │ (write_      │
                             │ --output-dir R   │           │           │  training_   │
                             └──────────────────┘           │           │  record)     │
                                                            ▼           └──────┬───────┘
                                                 ┌────────────────────┐        │
                                                 │ verify_onnx        │◀───────┘
                                                 │ (runtime + prov.)  │
                                                 └──────────┬─────────┘
                                                            │
                                                            ▼
                                                    ┌──────────────┐
                                                    │  ship to     │
                                                    │  canary      │
                                                    │  ring        │
                                                    └──────────────┘
```

Every arrow is content-addressed: the manifest's `sample_sha256` flows into
the training record's `baseline_sha256`, which the release gate re-verifies
against the manifest. A step that skipped a hash cannot pass the gate.

## Registry layout

```
ml/
├── datasets/
│   └── baselines/
│       ├── linux-wsl2-solkapc-2026-09-09/            ← legacy, pre-#170
│       │   └── baseline_benign.jsonl                 ← 71 samples, no manifest
│       ├── linux-wsl2-solkapc-2026-09-09-v2/         ← canonical example (#192)
│       │   ├── baseline.jsonl                        ← 423 samples
│       │   └── manifest.json
│       └── windows-solkapc-2026-09-08/               ← legacy, pre-#170
│           └── baseline_benign.jsonl                 ← no manifest
└── registry/
    ├── cmdline-iforest-linux/
    │   └── 0.1.0/
    │       ├── model.onnx
    │       ├── card.md
    │       └── training.json          ← written by train_linux.py
    └── cmdline-iforest-windows/
        └── 0.1.0/
            ├── model.onnx
            ├── card.md
            └── training.json          ← written by train_windows.py
```

`datasets/baselines/` is not committed as data in principle (`ml/datasets/README.md`
says so) — the captures themselves live outside git (large, potentially sensitive) —
but the manifests are, and small baselines have historically been committed as
bootstrap examples. That inconsistency is called out in the "Known limitations"
section below and will be resolved once the corpus outgrows a few hundred KB.

## How to

### Add a new baseline

```bash
# 1. Capture on a target host, produce events.jsonl (see agent/README.md).
edr-cli capture-events --out events.jsonl

# 2. Convert to a benign baseline.
python -m synthaea_ml.data.capture_to_baseline events.jsonl \
    --out ml/datasets/baselines/<slug>/baseline.jsonl

# 3. Write the manifest with the CLI (#187).
python -m synthaea_ml.data.manifest write \
    ml/datasets/baselines/<slug> \
    --platform linux \
    --os-version "WSL2 Ubuntu 24.04.5 LTS" \
    --workload-label dev \
    --capture-start 2026-09-09T12:18:25Z \
    --capture-end 2026-09-09T13:02:18Z \
    --capturer-ref "human-readable tag for the run"

# 4. Verify.
python -m synthaea_ml.data.manifest verify ml/datasets/baselines/<slug>
```

Bump `<slug>` on every new capture; never overwrite an existing baseline —
models already trained on it would silently disagree with the manifest.

Sensible `<slug>` shape: `<platform>-<host-descriptor>-<YYYY-MM-DD>`, matching
the current examples. The friendly directory name is just a rangement label —
the canonical dataset id inside `training.json` is
`default_dataset_name(baseline_dir)`, built from the manifest.

### Retrain a model

```bash
python -m synthaea_ml.training.train_linux \
    --dataset ml/datasets/baselines/linux-wsl2-solkapc-2026-09-09-v2 \
    --output-dir ml/registry/cmdline-iforest-linux/0.2.0
```

The trainer calls `dataset_version_from_manifest` on each `--dataset` (which
re-verifies the manifest before returning the `DatasetVersion`), fits the
model, writes `model.onnx` under `--output-dir`, and writes `training.json`
next to it via `write_training_record`. `train_windows.py` has the same
interface.

### Verify a model locally

```bash
# Default: warn on missing training.json, pass on legacy entries.
python -m synthaea_ml.export.verify_onnx \
    ml/registry/cmdline-iforest-linux/0.2.0/model.onnx

# Strict: fail on missing training.json. What CI runs.
SYNTHAEA_STRICT_PROVENANCE=1 python -m synthaea_ml.export.verify_onnx \
    ml/registry/cmdline-iforest-linux/0.2.0/model.onnx
```

With no arguments, `verify_onnx` walks every `ml/registry/*/*/model.onnx`.

### Enforce strict provenance in CI

Set `SYNTHAEA_STRICT_PROVENANCE=1` in the CI job that runs `verify_onnx`.
Once the two legacy entries are retrained, drop the env var and change the
default in `verify_onnx.py` to `strict=True`.

## Legacy state

Two entries predate this infrastructure and remain in the registry as
reference-only:

| Entry | Trained from | Provenance |
| --- | --- | --- |
| `cmdline-iforest-linux/0.1.0` | `ml/data/baseline_benign.jsonl` (71 rows, week 8, WSL2 lab) | none — pre-#170 |
| `cmdline-iforest-windows/0.1.0` | `ml/data/baseline_capture_windows.jsonl` + `baseline_capture2.jsonl` | none — pre-#170 |

Under `SYNTHAEA_STRICT_PROVENANCE=1` they fail `verify_onnx`. They are kept
for now as scoring references while the platforms iterate; their cards mark
them as below ship criteria (see `ml/README.md`, closing paragraph).

Migration path, now that #194 landed:

```python
# Both legacy baseline directories keep their `baseline_benign.jsonl` name.
# write_manifest already supported --baseline-filename; verify_manifest does
# too as of #194.
from pathlib import Path
from synthaea_ml.data.manifest import write_manifest, verify_manifest

for slug, platform, os_version in [
    ("linux-wsl2-solkapc-2026-09-09", "linux",   "WSL2 Ubuntu 24.04"),
    ("windows-solkapc-2026-09-08",    "windows", "11 24H2"),
]:
    d = Path(f"ml/datasets/baselines/{slug}")
    write_manifest(
        d,
        platform=platform,
        os_version=os_version,
        workload_label="dev",
        capture_start=...,
        capture_end=...,
        baseline_filename="baseline_benign.jsonl",
    )
    verify_manifest(d, baseline_filename="baseline_benign.jsonl")
```

The `--baseline-filename` flag on the CLI `verify` subcommand is a trivial
follow-up (~10 lines) called out in the #194 review; once it lands, the
migration above becomes pure CLI. Retraining then happens on the new v2-style
canonical baseline (see #192) and produces `registry/<model>/0.2.0`, retiring
the `0.1.0` entries.

## Known limitations

- **`verify` subcommand does not yet accept `--baseline-filename`.** The
  library function does (#194) but the CLI wrapper hasn't been extended — the
  work is a trivial ~10 line follow-up flagged in the #194 review. Until then,
  verifying a legacy baseline requires the Python one-liner shown in "Legacy
  state" above.
- **CRLF hash-drift on Windows contributors** — historic gap, **fixed by
  #198**. Nothing used to pin `ml/datasets/**/*.jsonl` to `text eol=lf`, so
  a contributor on Git-for-Windows with the default `core.autocrlf=true`
  got CRLF-rewritten baselines on checkout and every `verify_manifest`
  failed with a hash mismatch that looked like a real bug. #198 landed a
  `.gitattributes` covering exactly `ml/datasets/**/*.jsonl` and
  `manifest.json` — the schema/ml golden fixtures are read semantically
  (whitespace-insensitive JSON parsing), don't hash their own bytes, and
  don't need the same pinning.
- **No CI job runs `verify_onnx` yet.** `ml.yml` runs again on every push
  and PR (#318), but only lint and tests, so `SYNTHAEA_STRICT_PROVENANCE=1`
  runs locally only. Every PR touching `ml/**` must document a local
  `verify_onnx` run in its checklist.
- **`verify_onnx` runs Windows sanity samples against every model**
  (issue #191). The hardcoded `SANITY_CHECK_SAMPLES` in `verify_onnx.py` is
  imported from `train_windows`, so a Linux model shows all five Windows
  cmdlines as anomalies. Cosmetic — the runtime properties and provenance
  checks that gate ship are correct — but misleading in the logs. To be
  dispatched per-platform in a follow-up.
- **`ml/datasets/README.md` says "Data on disk — never committed" but small
  bootstrap baselines are committed** (`baseline_benign.jsonl` at 8.8 KB,
  the v2 baseline at 99 KB). The doc is out of sync with practice; either
  the README or the practice needs a reconcile once the corpus grows past
  a few hundred KB (Git-LFS/DVC decision already on the #44 radar).

## Related work

- Issue #44 — the umbrella for this infrastructure.
- PR #170 — dataset manifest (`data/manifest.py` + tests).
- PR #174 — trainer refactor to `--dataset` / `--output-dir`.
- PR #177 — training record (`registry/training_record.py` + tests).
- PR #180 — release gate hook in `verify_onnx` (`verify_provenance` +
  `SYNTHAEA_STRICT_PROVENANCE`).
- PR #187 — CLI wrapper `python -m synthaea_ml.data.manifest {write,verify}`.
- PR #192 — first real baseline through the pipeline
  (`linux-wsl2-solkapc-2026-09-09-v2`, 423 cmdlines, canonical example).
- PR #194 — `verify_manifest` accepts `--baseline-filename` for legacy
  captures (closes #190).
- Issue #191 — `verify_onnx` sanity samples hardcoded to Windows.
- Issue #196 — CRLF hash-drift on Windows contributors (closed by #198,
  which pinned `ml/datasets/**/*.jsonl` and `manifest.json` to LF).
- `ml/README.md` — the three rules this stack enforces.
- ADR-0002 — model artifacts are signed data delivered via canary rings, not
  binary-embedded assets. The provenance chain here is what those signatures
  cover.
