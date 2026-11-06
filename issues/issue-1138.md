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

## VM measurement, 2026-11-05 (Fedora 43, kernel 7.2.9, observe-only)

Capture: `lab/captures/test-1138-20261105/` (driver `t1138.sh`, `run-1138/events.ndjson`,
`scenario.log`, `analysis.txt`; outside git). Agent `agent-1127` (no #1138 rules), synthetic
`osqueryd.service`. Detail in ADR-0046 "Lab measurement".

Measured:
- No `file_open` for any `/sys/fs/cgroup/` write (sh `echo > memory.max`, python write to `memory.high`,
  `cgroup.freeze`, pid 1 via `systemctl set-property` / `freeze`): zero events with that path.
  Control write to `/tmp` gives `file_open` flags 577. Probe change 4a is needed, confirmed.
- `file_write` exists with fd and bytes only, no path.
- `set-property`: pid 1 opens `/etc/systemd/system.control/osqueryd.service.d/.#50-MemoryMax.conf...`
  (flags 524738); visible, but not a `/sys/` open and not used by any rule.
- argv empty on 5/8 `systemctl` and 3/3 `prlimit` execs (`freeze`, `thaw`, both `prlimit`):
  the exec rules would miss them on this build (#1118 race). `set-property` had argv.
- No `signal`, no `unit_stop` for freeze, set-property, direct writes, `prlimit`, OOM kill. `unit_stop`
  only for a plain `systemctl stop` (existing rule fired).
- OOM: kernel killed the hog of `osqueryd-oom.service` (`Result: oom-kill`); agent saw only the exec.

Still unmeasured: the #1138 rules themselves on a VM (needs a build with them: not rebuilt here);
open flags of `echo > memory.max` (no event exists); OOM or `RLIMIT_CPU` kill of the tool's main
process; `--runtime`; cgroup v1; probe change 4a (verifier on 5.15, volume); `prlimit64` tracepoint;
whether probe-side argv capture (ADR-0045) fixes the empty argv for these execs.
