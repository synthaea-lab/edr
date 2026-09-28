# lab/scenarios

Scripted, benign-by-construction attack simulations used to validate detections in the
lab. Each scenario documents the detections it is expected to trigger, so a run is an
assertion, not a demo.

To migrate from `old/lab` after review:

| Scenario | Simulates | Expected detections |
| --- | --- | --- |
| `beacon.sh` | Periodic same-destination C2 traffic | BEACON rule, correlation case |
| `dropper-chain.sh` | Download → write → execute chain | download-then-exec, T1105 correlation |
| `respawn-beacon.sh` | Beacon that respawns when killed | BEACON + SELF-SPAWN, case continuity |
| `lineage.sh` | Web-server-named process spawns a shell | T1059 — asserts eBPF parent lineage (ppid/parent_comm) is correct on every kernel row (#53) |
| `argv.sh` | Shell one-liner with a base64 decode in its arguments | T1059.004 — asserts argv/cmdline capture (`/proc/<pid>/cmdline`) is correct on every kernel row (#152) |
| `signal.sh` | Unprivileged SIGTERM/SIGKILL aimed at the agent, amid unrelated signal traffic | T1562.001 — asserts the kernel-side signal filter (zero events from unrelated signals) and, in its `kill`/`verify-kill` modes, SIGKILL attribution across an agent restart (#362) |
| `dns-exfil.sh` | Data chunked into high-entropy DNS subdomains | T1048.003/T1071.004 correlation (Windows agent only — no Linux DNS sensor yet) |
| `ld-preload-hijack.sh` | `LD_PRELOAD` pointed at a shared object outside the dynamic linker's trust set | T1574.006 — asserts the ExecEvent-side `check_ld_preload_hijack` rule (issue #363) |
| `persistence-write.sh` | A marker line appended to `~/.bashrc` | T1037.004/T1053.003 — asserts the write-intent-gated `check_persistence_write` rule |
| `log-clear.sh` | A log file under `/var/log/` deleted outright | T1070.002 — asserts the FileDeleteEvent-side `check_log_file_delete` rule (Linux only here; the exec-side `check_log_clear_exec` half needs a systemd-based row) |
| `encoded-powershell.ps1` | `powershell.exe -EncodedCommand <base64>` invocations | T1059.001 — asserts the ExecEvent-side `check_encoded_powershell` rule |
| `scheduled-task-persistence.ps1` | `schtasks.exe /Create` a demo task | T1053.005 — asserts the 4698 → `FLAG_PERSISTENCE_TASK_ARTIFACT` → `check_scheduled_task_persistence` end-to-end pipeline |
| `service-install-persistence.ps1` | `sc.exe create` a demo service (never runs) | T1543.003 — asserts the 7045 → `FLAG_PERSISTENCE_ARTIFACT` → `check_service_install_persistence` end-to-end pipeline |
| `create-account-persistence.ps1` | `net user /add` a benign local SAM account | T1136.001 — asserts the 4720 → `FLAG_PERSISTENCE_ACCOUNT_ARTIFACT` → `check_account_creation_persistence` end-to-end pipeline (local SAM only; T1136.002 domain accounts are out of scope) |
| `ransomware-rename-burst.sh` | Same-pid burst of file renames, each appending a suffix onto its own old name | T1486 — asserts `check_mass_rename_pattern`'s extension-agnostic mass-rename detection (issue #262) |

The four `.ps1` scenarios above are the Windows demo surface — see `../../demo/`
for the runbook that chains them in the reviewer-facing order.

New scenarios follow the same shape: one script, one documented expectation list,
runnable against any platform's agent from the VM matrix (`../vagrant`).

Windows scenarios must run on a stock Windows PowerShell 5.1 under any locale
(#433). They dot-source `common.ps1` and keep to its three rules: ASCII-only source
(`tools/check-ps1-ascii.py`, run by CI), locale-dependent arguments built from the
current culture (`Get-FarFutureDate`), and every native call checked
(`Invoke-Native`), so a failed step throws instead of reporting success.

## Machine-readable expectations

Each `.sh` scenario above has a YAML sidecar (`<name>.yaml`, decided in issue #44:
format + expected-detections schema) that makes the table row above machine-parsable
— a replay engine can validate or list scenarios without executing anything. Shape:

```yaml
name: <scenario stem>
platform: linux | windows
script: <name>.sh
simulates: >
  Free-text description of what the scenario simulates.
expected_detections:
  - technique: "<exact Alert.technique / CorrelationAlert.technique string>"
    rule: <crates/rules or crates/correlator fn name>   # doc-only, not asserted at replay time
    min_count: 1    # >= 1
    tolerance: 0     # allowed overshoot: pass iff observed_count <= min_count + tolerance
notes: null
```

`technique` matches by exact string against `AlertRecord.technique` in `alerts.ndjson`
(`crates/sinks/src/lib.rs`) — both `Alert` and `CorrelationAlert` converge there, so one
schema covers rule-engine and correlator-engine detections alike. This binds into the
model record's `scenario_replays` (ADR-0009, `docs/adr/0009-model-record-scenario-replay-binding.md`):
`ExpectedDetection`/`ObservedDetection` there use the same field names.
Scenario/schema decisions live on issue #44; the replay engine itself is separate,
still-unwritten work.
