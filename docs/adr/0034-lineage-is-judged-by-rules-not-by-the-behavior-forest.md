# ADR-0034: The process lineage is judged by rules, not by the T1 behavior forest

- **Status**: accepted
- **Date**: 2026-10-13

## Context

#617 asked whether adding the parent lineage (six binary columns: has a parent, parent is a
shell / web server / Office app, parent path is system / suspicious) to the T1 behavior vector
improves an Isolation Forest. The vector was cmdline (9) + correlation (8) + lineage (6) = 23.
It was measured on real captures from the lab VM (`t1_lineage_gain`, 20 random splits of the
distinct benign vectors, paired per split, trainer hyperparameters, 5 FP/endpoint/day):

| malicious subset (second benign capture) | vectors | AUC 17 | AUC 23 | paired gain |
| --- | --- | --- | --- | --- |
| odd lineage (web-server or Office parent, or parent in `/tmp`, `/var/tmp`, `/dev/shm`) | 26 | 0.83 | 0.98 | positive in 20 / 20 |
| ordinary lineage | 303 | 0.65 | 0.56 | -0.095, 0 / 20 |
| all | 329 | 0.66 | 0.59 | -0.078 +/- 0.020, 0 / 20 |

92% of the malicious vectors have a lineage identical to the benign data's. For them the six
extra columns dilute the forest, whose random splits land on columns that do not separate.
Scoring the lineage in the forest trades detection of odd-lineage attacks against detection of
the rest.

A prototype of the strong rule on the same captures: "a web-server or Office-named parent spawns
a shell" matched 0 of 12,381 benign incarnations and 20 of 329 malicious ones. A parent running
from a suspicious path matched 1.8% of benign incarnations and 2.7% of malicious ones, which
separates almost nothing (and the benign capture runs one job from `/tmp` on purpose). A
web-server parent alone is more frequent in benign than in malicious (a web application runs
programs): noise.

## Decision

1. **The T1 vector is cmdline (9) + correlation (8) = 17 features.** Python
   (`synthaea_ml.features.t1`) and Rust (`ml::features::t1`) drop the lineage block together, and
   the parity fixtures (`t1_golden.jsonl`, the scorer ONNX fixture) are regenerated.
2. **The parent is judged by rules.** A web or database service spawning a shell on Linux is
   `check_web_server_spawns_shell` (T1059). An Office or PDF application spawning an interpreter
   on Windows is `check_parent_suspect` (T1204/T1059). Neither needed to change.
3. **No lineage mutator runs against the T1 model.** The parent is not scored, so an escape rate
   over `fake_parent_name` / `parent_path` / `remove_lineage` would be a flattering zero. The
   mutators and the lineage extractor stay (parity-tested); lineage evasion belongs to the rules'
   tests.
4. **`t1_lineage_gain` keeps its own 23-column vector** (T1 plus the lineage) so the measurement
   can be re-run on a better capture. It is the evidence for this decision and the way to revisit
   it.

## Consequences

- A forest trained here is no longer diluted for ordinary-lineage attacks; its measured AUC
  returns to the 17-feature figure.
- An attack with an odd parent that is not a web or database service spawning a shell is covered
  by no model and no rule. Known gaps: on Linux an Office-named parent (LibreOffice's
  `soffice.bin`) and a binary dropped in `/tmp`, `/var/tmp` or `/dev/shm` that spawns children.
  The first is rare on Linux hosts; the second matches 1.8% of benign incarnations and was not
  turned into a rule or evidence.
- **Not done: a weak, capped "suspicious parent path" evidence** (the shape of the rarity
  evidence of ADR-0020). On these captures it separates almost nothing (1.8% vs 2.7%), so it
  would add noise to the belief. Reconsider on a capture whose benign part reflects a real host.
- **Evidence limits.** One lab host, one agent, one session; the web-application parent appears
  in 5.5% of the benign vectors because the workload puts it there; the odd-lineage subset is 26
  vectors from four scripts written to be odd, so its gain is not an estimate for real attacks.
- No T1 model ships and the agent does not load `ml::BehaviorScorer`, so no deployed model
  changes width. The retrain of the shipped T1 model (#617 box 1) remains, now on 17 features.
