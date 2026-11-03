# ADR-0044: The Linux sensor reads the head of a process's argv in the exec probe

- **Status**: accepted (decision taken under the owner's delegation, 2026-11-03; implementation not started)
- **Date**: 2026-11-03

## Context

The Linux sensor reads `argv` from `/proc/<pid>/cmdline` when it drains an exec event from the ring
buffer (`crates/sensors/linux/userspace/src/proc.rs`, accepted in #152 to avoid a frozen
`mm_struct` offset). A process that exits before the drain leaves nothing to read: its exec event
carries `argv: []` and `cmdline: ""`. `proc.rs` documents the race and calls the probe-side read "a
separate follow-up". #1118 measured it, on Fedora 43 (7.2.9) and Rocky 9.8 (5.14), with the agent of
`main` at `81cc6c52`, 300 `true`, 100 `sleep 0.3`, 100 `sudo -n systemctl is-active` per phase:

| process | idle | under CPU load |
| --- | --- | --- |
| `true` | 1-3 % empty | 100 % empty |
| `sleep 0.3` | 0 % | 87-91 % |
| `sudo` | 86-87 % | 88-98 % |
| `systemctl` | 97-99 % | 97-100 % |

Rules that read a command line therefore see an empty one for most short-lived processes, and the
administrative commands that matter (`systemctl`, `sudo`, `reboot`, `kill`) are exactly the short-lived
ones. In #1085 / PR #1102, 11 of 12 `systemctl stop` of a listed tool reached UNEXPLAINED-UNIT-STOP
with the wrong reason ("no `systemctl stop` of it") on both OSes. The `/proc` read cannot be made
reliable by trying harder: the process can be gone before the drain thread is scheduled.

## Decision

**Read the first 1 KiB of the argument block in the `sched_process_exec` probe, and keep the `/proc`
read as the fallback for the tail and for kernels where the probe read fails.**

- The probe is a raw tracepoint that receives the `task_struct *` and the `linux_binprm *`; userspace
  already derives member offsets from the kernel's BTF and hands them to the probe (the scheduler and
  inode-setattr offsets in `btf.rs`, the siginfo offsets of #1103). The argument block is
  `mm->arg_start .. mm->arg_end`: add `task_struct.mm`, `mm_struct.arg_start` and `mm_struct.arg_end` to
  that set. The probe reads up to 1 KiB from `arg_start` with one `bpf_probe_read_user_buf` call (a
  single helper call, not a loop, so it adds little to the verifier budget on pre-6.6 kernels).
- The event gains a fixed `argv_head` buffer and its length (a wire change: `WIRE_VERSION` bump, the
  exec record grows by about 1 KiB in the ring). Userspace splits it on NUL, and reads `/proc` only to
  extend it when `arg_end - arg_start` is larger than what the probe took **and** the process is still
  alive. The result is cut at the capture budget that #1116 introduces (`ARGV_CAPTURE_BUDGET`, 32 KiB, open
  at the time of writing) and its `cmdline_truncated` flag says whether the whole block was seen.
- 1 KiB is chosen from #1112's measurement of 3,451 benign execs (p99.9 347 B, max 1,661 B): it holds
  the command line of well over 99.9 % of them whole.

### Rejected

- **Keep `/proc` and retry or read faster.** The race is inherent: the process is gone, not slow.
  Measured above, including idle.
- **Read `argv` at `sys_enter_execve`** (the `execsnoop` way). The syscall can fail after that point and
  the exec is not yet the process's own, so an exec event would have to be paired with a later one, and
  `execveat`, scripts and `fexecve` need their own care. The raw `sched_process_exec` already has the
  right moment (the exec has happened) and the BTF offset mechanism.
- **`task_work` to read `/proc` from the probe.** Not available on the 5.14 kernels in the lab matrix.
- **Raise the drain priority or enlarge the ring.** Does not help a process that lives a few ms.
- **Do nothing and make each rule tolerate an empty `argv`.** Each rule would then be blind to the
  commands it exists to catch; the rules cannot tell "empty because short-lived" from "empty because
  there were no arguments".

## Consequences

- Rules reading a command line (`SECURITY-TOOL-STOP`, the stop-explained joins of #1102, the `base64`
  rule, the Sigma content, the ML command-line features) see the command line of short-lived processes
  too. The exec path of #1102 stops mislabelling most `systemctl stop`.
- `cmdline_truncated` (#1116, once merged) becomes meaningful for a process that exited: `false` then means the
  whole block was read, not "no cut seen".
- Cost: 1 KiB more per exec event in the ring buffer and in the per-CPU scratch (the ring is already
  shed under pressure and counted), one more helper call per exec, and three more BTF members that
  must resolve. A kernel without them falls back to today's behaviour.
- A process can rewrite its own argument region (`PR_SET_MM_ARG_*`, or writing through `arg_start`)
  between the exec and a later `/proc` read. Reading it in the probe, at the exec, closes that gap for
  the head, which the `/proc` read documents as open.
- Windows and macOS are unchanged here (Windows takes the command line from the ETW event, macOS from
  the Endpoint Security message).

## Not verified, to settle in the lab before this is built on

- That `mm->arg_start` and `arg_end` are set when `sched_process_exec` fires, on 5.14 and on 7.2: by
  reading the kernel (`create_elf_tables` sets them before the exec returns) it should be, but binary
  formats other than ELF and scripts were not checked.
- The verifier cost on the 5.14 build of the probe and on the largest existing exec path.
- The effect of the larger exec record on ring drops under the load used by #1118 (the measurement
  script is `lab/captures/test-1118-20261103/argv-test.sh`: re-run it with the new probe, the target is
  0 % empty for `true`, `sudo` and `systemctl` idle and under load).
- A process that execs with arguments past the first 1 KiB: the head is exact, the tail comes from
  `/proc` while alive and is otherwise lost, flagged by `cmdline_truncated`.
