# rules/sigma

Sigma rules evaluated on-device by the `sigma` engine crate. Layout: one directory per
platform, descriptive file names (the directory carries the platform, so no `lnx_`/
`win_` infix): `linux/base64_pipe_shell.yml`, `windows/powershell_encoded.yml`.

Every rule must stay inside the engine's supported subset (`crates/sigma` docs) — the
engine rejects out-of-subset rules loudly at load time, and CI enforces it: the
content workflow runs the sigma crate's content test, which loads this whole tree and
asserts every rule both parses AND fires on a crafted matching event
(`crates/sigma/tests/content.rs`). Adding a rule means adding its samples beside it:
`<rule>.samples.json` with one `matching` and one `non_matching` event (ADR-0031), e.g.
`{"matching": {"image": "/bin/bash", "cmdline": "..."}, "non_matching": {"image": "...", "cmdline": "...", "note": "the boundary this probes"}}` A rule on `ParentImage` adds `"parentimage"` to both events.
A rule nothing can trigger is dead content.
