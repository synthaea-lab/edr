# docs

Documentation is written fresh, alongside the code it describes (`old/docs` stays a local,
untracked reference). Files below are placeholders until their subsystem has real code.

| Section | Contents |
| --- | --- |
| `vision.md` | Why the project exists, goals, non-goals |
| `roadmap.md` | Milestones and current status |
| `architecture/` | System-level design: agent, control plane, event schema, threat model |
| `sensors/` | The sensor contract and one document per platform |
| `detection/` | Rules, Sigma, YARA, correlation, ML — plus the ten-layer stack map (`layers.md`), the generated ATT&CK coverage matrix (`attack-coverage.md`, from `tools/attack-coverage.py`), and detection-as-code contract |
| `operations/` | Deploying and operating the agent and control plane |
| `development/` | Contributor guides: setup, building, testing |
| `adr/` | Architecture decision records |
