# rules — Detection Content

Detection content shipped to agents, kept separate from engine code so it can ship on its
own cadence (canary rings). To be migrated/curated from `old/rules` after review.

| Path | Purpose |
| --- | --- |
| `sigma/` | Sigma rules — behavioral detections on the event stream, organized by platform and ATT&CK technique |
| `yara/` | YARA rules — file and memory content scanning, organized by category |
| `ioc/` | IOC feeds (proposed, #934) — one `<feed>.txt` per file, `sha256:` / `ip:` / `domain:` lines (ADR-0038); CI loads each through the engine and the server's feed builder |
