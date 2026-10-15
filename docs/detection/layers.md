# The Detection Stack — Ten Layers

Defense in depth, from cheapest/most-brittle to most-contextual. Each layer catches
what the previous one structurally cannot; an attacker must beat all of them at once,
and the cost concentrates upward (rewriting a payload beats L1 in minutes; producing
a normal-looking process lineage across a fleet over time has no cheap rewrite).

| # | Layer | Runs | What implements it | Status |
| --- | --- | --- | --- | --- |
| 1 | Signatures / hashes | device | `intel` (IOC hash/IP/domain sets) · `yara` (content patterns) · `enrich` (SHA-256 + signature verdicts) | yara built · enrich built · intel drafted (#60) |
| 2 | Static ML | device | T0 models (`crates/ml` inference, `synthaea_ml` training): cmdline anomaly today, static file features later | in progress (#13) |
| 3 | Behavioral rules | device | `rules` (stateless + stateful) · `sigma` content | built |
| 4 | Behavioral ML | device | `correlator` behavior vectors + calibrated Bayesian LLR (T1) · T2 correlation scorer | Bayes built · T2 with #13 |
| 5 | Reputation / prevalence | server → device | `server/prevalence`: fleet first-seen/rarity, fed back into T0/T1 features and correlator evidence | counters, console triage line, snapshot format, agent loader and capped correlator evidence built; snapshot publication and calibration open (#76) |
| 6 | Attack-chain correlation | device | `correlator` co-occurrence rules + cases | built |
| 7 | Cross-endpoint correlation | server | `server/fleet`: fleet cases + adaptive posture | drafted (#62) |
| 8 | Identity / network / cloud | server | XDR scope: identity signals arrive with `server/disruption` connectors; network/cloud ingestion is post-v1 (kept deliberately out of the agent) | direction |
| 9 | Threat intelligence | server → device | `intel` feed pipeline (STIX/TAXII/MISP → indicator sets + IOA→content conversion) | drafted (#60) |
| 10 | Human / MDR intelligence | server | `server/hunt` (hunts graduating into content) · `response::live` · `server/forensics` · `server/assistant` · case workflow | drafted |

Cross-cutting spine, not a layer: **MITRE ATT&CK mapping** — every detection carries
technique identifiers (rules/sigma/correlator already emit them; formalized as
structured fields + a generated coverage matrix), so every layer's output lands on
one shared map, and coverage claims are generated, never hand-maintained.

Reading the table operationally: layers 1–4 and 6 are the on-device budgeted path
(verdicts in milliseconds, works offline); 5, 7–10 are where the control plane earns
its keep — and layers 5+7 together are the fleet-derived half of the thesis: the part
an attacker cannot reproduce by downloading our binaries and content.

The server-side layers share one substrate: the telemetry lake
(`server/datalake`) with `server/cloud-detection` running on it in three modes —
streaming on ingest, scheduled sweeps for windows no device buffer can hold, and
**retrospective detection**: new content replayed over history, turning yesterday's
unknown into today's case. Cloud detection augments the device; it is never an
excuse to thin layers 1–4/6, which are what protect an offline endpoint.
