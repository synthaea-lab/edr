# docs

Documentation is written fresh, alongside the code it describes (`old/docs` stays a local,
untracked reference). Files below are placeholders until their subsystem has real code.

| Section | Contents |
| --- | --- |
| `vision.md` | Why the project exists, goals, non-goals |
| `roadmap.md` | Milestones and current status |
| `architecture/` | System-level design: agent, control plane, event schema, threat model |
| `sensors/` | The sensor contract and one document per platform |
| `detection/` | Rules, Sigma, YARA, correlation, ML — plus the ten-layer stack map (`layers.md`), the generated ATT&CK coverage matrix (`attack-coverage.md`, from `tools/attack-coverage.py`), the Windows download-provenance coverage map (`download-provenance.md`), the credential-file read rule (`credential-files.md`), the storage and paste egress rule (`egress-domain.md`), the staging-directory rule (`staging-dir.md`), the security-tool stop rule (`security-tool-stop.md`), the web-server lineage rules for Windows and macOS (`web-server-lineage.md`), the first-seen and odd-hour logon rules (`first-seen-logon.md`), the on-device IOC matching engine (`ioc-matching.md`), and detection-as-code contract |
| `operations/` | Deploying and operating the agent and control plane |
| `development/` | Contributor guides: setup, building, testing |
| `adr/` | Architecture decision records |
