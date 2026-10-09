# lab/ml-capture: the real capture behind the T1 retrain (#617)

The T1 behavior model scores one process on its command line (9 features), its correlation
context (8) and its parents (6). #617 asks whether the 23 features detect more than the same
vector without the parents, at the same false-positive budget. That can only be answered from a
**real** capture, with these constraints:

- the benign part must **vary in its lineage**. An Isolation Forest never splits on a feature
  that is constant in training, so a benign capture whose processes all hang under one shell
  cannot teach it that another parent is odd. `ml/tests/test_t1_lineage_gain.py` pins this
  (`test_a_lineage_the_benign_capture_never_varied_is_invisible_to_the_model`);
- it must come from a real kernel with pids, process generations and parents, not WSL2 (every
  event there has `ppid=0`);
- the malicious part is the repository's own lab scenarios: benign by construction, mostly
  started from a shell. A lineage gain can only show on a scenario whose parent is odd
  (`lineage.sh`). **Say that when reporting a number.**

## Procedure (lab VM, isolated; see the `synthaea-lab-vm` notes: snapshot, NAT NIC detached)

All commands run on the VM as root unless noted; the agent is built from `main`
(`cargo build --release -p agent`).

1. **Benign capture.** Two terminals:

   ```
   sudo ./agent capture-events --output events.jsonl          # A, leave running
   DURATION=1200 ./lab/ml-capture/benign-workload.sh         # B, as the user whose activity to model
   ```

   Run it as an ordinary user, then again as root (the system manager becomes the parent of the
   `systemd-run` units), and, if you can, while using the VM normally (ssh sessions, a package
   query). Stop the capture afterwards. Keep each run's `events.jsonl` apart.
2. **Malicious capture** with a fresh capture file:

   ```
   sudo ./agent capture-events --output events-malicious.jsonl        # A
   sudo ./lab/ml-capture/malicious-run.sh out-malicious               # B
   ```

   `out-malicious/run.json` holds the runner's pid and the window of the run. A scenario that
   failed is listed under `failed`; read its log before trusting the run.
3. **Bring the files to the host** and lay them out (data on disk, never committed):

   ```
   ml/datasets/captures/linux-lab-<date>/events.jsonl      # benign
   ml/datasets/labeled/linux-lab-<date>/events.jsonl       # malicious, + run.json beside it
   python -m synthaea_ml.data.manifest write \
       --platform linux --os-version "Fedora 44" --workload-label dev \
       --capture-start <ISO> --capture-end <ISO> --baseline-filename events.jsonl \
       ml/datasets/captures/linux-lab-<date>/
   ```

   (Several benign captures can be passed to `--dataset`; give each its manifest.)
4. **Train** the shipped model, with the T1 robustness card on the malicious capture:

   ```
   python -m synthaea_ml.training.train_behavior \
       --dataset ml/datasets/captures/linux-lab-<date>/ \
       --output-dir ml/registry/behavior-iforest-linux/0.1.0/ \
       --robustness-scenarios lab/scenarios/beacon.yaml lab/scenarios/lineage.yaml \
       --robustness-events ml/datasets/labeled/linux-lab-<date>/events.jsonl
   python -m synthaea_ml.evaluation.robustness_cli verify \
       --model-dir ml/registry/behavior-iforest-linux/0.1.0/ --max-escape-rate 0.15
   ```

   `train_behavior.py` refuses fewer than 20 distinct benign vectors: capture longer.
5. **Measure the gain** (what #617 is for):

   ```
   python -m synthaea_ml.evaluation.t1_lineage_gain \
       --benign-dataset ml/datasets/captures/linux-lab-<date>/ \
       --malicious-capture ml/datasets/labeled/linux-lab-<date>/events.jsonl \
       --root-pid <root_pid> --start-ns <start_ns> --end-ns <end_ns> \
       --output ml/registry/behavior-iforest-linux/0.1.0/t1_lineage_gain.json
   ```

   It fits the 17-feature and the 23-feature model on 20 random splits of the distinct benign
   vectors (same hyperparameters, same FP budget as the trainer) and reports detection rate,
   false-positive rate on a held-out benign part and ROC AUC, with the paired per-seed gain
   and the number of splits where the lineage is not worse.

## Reading the result

- Report the **counts** (distinct benign and malicious vectors) next to every rate: with a few
  hundred benign vectors the conformal threshold at 5 FP/endpoint/day sits at the very bottom
  of the benign scores, so the detection rate is strict and noisy; the AUC does not depend on
  the threshold and is the steadier number.
- A gain of about zero is a result, not a failure: it says the scenarios, or the benign capture,
  do not exercise the lineage. Do not tune hyperparameters on this data (the trainer says why).
- The report goes next to the model; `model_record.json` has no field for it yet, so "recorded
  in `model_record.json`" (box 1 of #617) needs a registry-schema change of its own, or the box
  is reworded to name this file.
- Not covered by one run: other hosts, a longer benign period, attacks that are not these
  scenarios, the packaged unit, and the agent loading the scorer (`sink.rs` loads T2 only).
