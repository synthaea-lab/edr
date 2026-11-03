# ADR-0045: The Linux sensor reads the head and the tail of a process's argv in the exec probe

- **Status**: proposed
- **Date**: 2026-11-03

## Context

The Linux sensor reads `argv` from `/proc/<pid>/cmdline` when it drains an exec event from the ring
buffer (`crates/sensors/linux/userspace/src/proc.rs`, accepted in #152 to avoid a frozen
`mm_struct` offset). A process that is gone, or whose `/proc` entry cannot be read, by the time the
drain runs leaves nothing: its exec event carries `argv: []` and `cmdline: ""`. `proc.rs` documents
the race and names the probe-side read as a follow-up. #1118 measured it, on Fedora 43 (7.2.9) and
Rocky 9.8 (5.14), with the agent of `main` at `81cc6c52`. The workload per run was 300 `true`, 100
`sleep 0.3` and 100 `sudo -n systemctl is-active auditd`, first idle and then with one `yes` per vCPU:

| process | idle | under CPU load |
| --- | --- | --- |
| `true` | 1-3 % empty | 100 % empty |
| `sleep 0.3` | 0 % | 87-91 % |
| `sudo` | 86-87 % | 88-98 % |
| `systemctl` | 97-99 % | 97-100 % |

Two causes show in the table. `systemctl` and `sudo` are empty most of the time even on an idle host:
they exit within milliseconds, before any drain. `sleep 0.3` is 87-91 % empty only under load: the
drain was then more than 300 ms behind (a backlog or a scheduling delay), not a process that is gone
in milliseconds. Either way the result depends on the drain latency and on the process lifetime, and a
read done later cannot be made to depend on neither. The administrative commands that matter
(`systemctl`, `sudo`, `reboot`, `kill`) are exactly the short-lived ones, so rules that read a command
line see an empty one for them. In #1085 / PR #1102, 11 of 12 `systemctl stop` of a listed tool reached
UNEXPLAINED-UNIT-STOP with the wrong reason ("no `systemctl stop` of it").

The other reads the drain path does after the fact (`/proc/<pid>/environ`, `cwd`, `exe`, the fallbacks of
the parent image in `parent_image.rs`) share the same lag. They are out of scope here and keep the
current behaviour; the executed image itself is already read authoritatively in the probe.

## Decision

**Read the argument block in the `sched_process_exec` probe, as a head and a tail window plus its total
length, and keep the `/proc` read as the fallback when the probe read is not available.**

- The probe is a raw tracepoint that receives the `task_struct *` and the `linux_binprm *`; userspace
  derives member offsets from the kernel's BTF and hands them to the probe. The argument block is
  `mm->arg_start .. mm->arg_end`, so the three new members are `task_struct.mm`, `mm_struct.arg_start` and
  `mm_struct.arg_end`.
- **What is captured, at the exec.** `argv_total_bytes` (`arg_end - arg_start`) always; then up to
  `ARGV_WINDOW_BYTES` = 1,024 bytes of the block: all of it when it fits, otherwise the first 768 bytes
  (`argv_head`) and the last 256 bytes (`argv_tail`, read from `arg_end - 256`). Each read is one clamped
  `bpf_probe_read_user_buf` call into a fixed buffer, the pattern the probe already uses for the DNS and
  TLS payloads (`ebpf/src/main.rs`, "the length is clamped first so the verifier sees an upper bound, and it
  is one helper call, not a byte loop"). A variable-length read into the buffer needs the same pre-clamp on
  the 5.14 verifier; the verifier outcome is **not verified**.
- **Why a tail as well as a head.** A head-only capture lets a process pad its arguments past the window,
  put the payload at the end and exit within milliseconds: the tail is lost and nothing can be read
  later, so padding would beat the race every time (the evasion #1116 is reviewed for). The tail window
  closes the most direct form of it. A payload in the **middle** of a padded block is still omitted; that case
  is handled by the flag and the rule below, not by a larger window.
- **What userspace builds.** `argv` is the whole tokens of the head and of the tail; a token cut by a window
  edge is not in `argv` and its bytes stay in the `cmdline` string, which reads `head`, then a marker
  `…[N bytes omitted]…` where `N = argv_total_bytes - head - tail`, then `tail`. Consumers of `cmdline`
  (the Sigma content, the `base64` rule, the ML command-line features) therefore see the real beginning and
  the real end of a long command line and the marker, never a silently shortened one. Whatever the `/proc`
  read can add after the exec (the middle of a block that the process rewrote or that was cut by the budget)
  is **not exec-time** and is not used to fill the omitted middle: the gap is stated by the marker.
- **`cmdline_truncated`.** #1116 sets it when the capture budget (`ARGV_CAPTURE_BUDGET`, 32 KiB, #1116 is not
  merged) cuts the command line. This ADR sets the same flag when part of the block was not seen: the middle
  was omitted, or the probe read failed. The two reasons are told apart by `argv_total_bytes`, which the event
  now carries: above the budget it is the budget cut, between the window and the budget it is the window.
  After the process is gone `arg_end - arg_start` cannot be read any more, which is why the probe sends it.
- **A rule on the flag is part of this work, not a follow-up.** An exec whose argument block exceeds what was
  captured is itself evidence (a benign exec in #1112's sample of 3,451 never exceeded 1,661 bytes, and its
  p99.9 is 347 bytes). A stateless rule, Low, on `cmdline_truncated` with the omitted length in the message,
  lands with the probe change; the technique id and the exact severity are chosen at implementation, after
  counting how many benign execs of the sample exceed 1 KiB (not counted).
- **Wire and ring.** The exec record is `size_of::<ExecEvent>()` = 360 bytes today (measured with a throwaway
  test), and `EXEC_EVENTS` is 256 KiB: about 712 records once the 8-byte ring header is counted. Adding a
  fixed 1,024-byte buffer to every record would make it about 1,400 bytes and the ring about 188 records, 3.8
  times fewer, so a storm would shed sooner and a shed exec is gone. The decision is therefore a
  **variable-length record**: the fixed part stays where it is, `argv_total_bytes` and the two lengths are added
  to it, and only the bytes actually read follow (`output` of a slice of the scratch up to the head and tail
  lengths, the length clamped for the verifier; whether the 5.14 verifier accepts the variable `output` is
  **not verified**, the fallback is the fixed buffer with the ring raised). A typical record then grows by
  the command line itself (about 100 to 350 bytes), and the ring is raised to **512 KiB** to keep about
  the current capacity or better. `WIRE_VERSION` is bumped, and the per-CPU scratch grows by 1 KiB per CPU.
- **Failure path.** `bpf_probe_read_user_buf` fails (`-EFAULT`) on a page that is not resident. The argument
  pages were written into the new stack by `execve` itself (`copy_strings`) and `create_elf_tables` sets
  `arg_start`/`arg_end` before the exec returns, so they should be resident when the tracepoint fires; this is
  from reading the kernel, not verified. On any failed read the probe sends a zero head length and a flag, and
  userspace falls back to the `/proc` read as today.
- **Fallback when the offsets cannot be resolved.** The three members go through the **optional** loader path,
  like the `inode_setattr` offsets (`read_inode_setattr_offsets`, `ebpf.rs`), not through
  `read_scheduler_field_offsets`, whose failure stops the sensor ("could not read required fields from kernel
  BTF"). A kernel where they cannot be resolved loads the probe with the argument read disabled, logs a
  warning, and keeps today's `/proc` behaviour; a test with a BTF that lacks `arg_start` must show the sensor
  still starting. A kernel without `/sys/kernel/btf/vmlinux` already cannot run the sensor.

### Rejected

- **Keep `/proc` and retry or read faster.** The result depends on the drain latency and the process
  lifetime; neither can be controlled from the drain thread. Measured above, including idle.
- **Read `argv` at `sys_enter_execve`** (the `execsnoop` way). The syscall can fail after that point and the exec
  is not yet the process's own, so an exec event would have to be paired with a later one, and `execveat`,
  scripts and `fexecve` need their own care. `sched_process_exec` is the right moment and has the BTF offset
  mechanism.
- **`task_work` to read `/proc` from the probe.** Not available on the 5.14 kernels in the lab matrix.
- **A head-only capture.** Padding then hides the payload deterministically, see above.
- **A fixed 1 KiB buffer in every record.** It divides the ring capacity by about 3.8 for a sample whose
  p99.9 is 347 bytes.
- **Making every rule tolerate an empty `argv`.** Each rule would be blind to the commands it exists to catch;
  the rules cannot tell "empty because short-lived" from "empty because there were no arguments".

## Consequences

- Rules reading a command line (`SECURITY-TOOL-STOP`, the stop-explained joins of #1102, `base64`, the Sigma
  content, the ML command-line features) see the command line of short-lived processes, and the end of a long
  one. The exec path of #1102 stops mislabelling most `systemctl stop`.
- `cmdline_truncated` means "part of the argument block was not seen", for a process that exited too, and
  `argv_total_bytes` says how much. A process that pads its block now raises a Low rule instead of silently
  losing its tail.
- A process can rewrite its own argument region (`PR_SET_MM_ARG_*`, or writing through `arg_start`) between the
  exec and a later `/proc` read. The head and the tail read in the probe are exec-time; a `/proc` read of
  the middle would not be, so it is not used.
- Cost: the record grows by the command line actually read (and the ring doubles to 512 KiB), one or two more
  helper calls per exec, three more BTF members that must resolve, a `WIRE_VERSION` bump. The ring is shed
  and counted under pressure as today; the new capacity is the figure above, to be re-measured.
- Windows and macOS are unchanged here (Windows takes the command line from the ETW event, macOS from the
  Endpoint Security message). The offsets are the same width on LP64, so aarch64 is a low risk, but the lab
  matrix is x86 and aarch64 is not verified.

## Not verified, to settle in the lab before this is built on

- That `mm->arg_start` and `arg_end` are set when `sched_process_exec` fires, on 5.14 and on 7.2: by reading
  the kernel (`create_elf_tables`) they should be; binary formats other than ELF and scripts were not
  checked. How `arg_start`/`arg_end` sit in `mm_struct`'s BTF was not checked either.
- The verifier cost on the 5.14 build of the probe and on the largest existing exec path, including the
  variable-length `output`.
- The ring drops under the load of the #1118 measurement: re-run its workload (300 `true`, 100 `sleep 0.3`,
  100 `sudo -n systemctl is-active auditd`, idle and with one `yes` per vCPU) with the new probe; the target is
  0 % empty for `true`, `sudo` and `systemctl`, idle and loaded, and no more ring drops than today.
- The number of benign execs above 1 KiB in a larger sample, to set the severity of the rule.
