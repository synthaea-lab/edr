# Issue 1138: kernel-mediated stop of a security tool

Branch `feat/1138-kernel-mediated-stop`. Decision in `docs/adr/0046-kernel-mediated-stop-of-a-security-tool.md`.

Built, no VM: exec rule for `systemctl freeze` / `set-property` limits (Medium), `prlimit --pid`
CPU/AS (Low, no tool named), cgroup-file open rule (Medium, no producer yet). Tests in
`crates/rules/src/tests/securitytool.rs`.

Needs a VM before it can be called done: reproduce the three kernel paths; measure the open flags
and path of `echo > memory.max`; probe change letting write-intent `/sys/fs/cgroup/` opens through
`is_filtered_path` (verifier on 5.15, ring volume); `prlimit64` tracepoint (needs a schema version).

Doc conflict: #1114 adds a "Kernel-mediated stops" bullet to `docs/detection/security-tool-stop.md`
and says "Follow-up: #1138"; this change adds a section of the same name. Merge: keep the bullet short
and point it at the section.
