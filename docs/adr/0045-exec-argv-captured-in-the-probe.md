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
in milliseconds. In both cases the result depends on the drain latency and on how long the process
lives, and neither can be controlled from the thread that reads `/proc` afterwards. The administrative
commands that matter (`systemctl`, `sudo`, `reboot`, `kill`) are exactly the short-lived ones, so rules
that read a command line see an empty one for them. In #1085 / PR #1102, 11 of 12 `systemctl stop` of a
listed tool reached UNEXPLAINED-UNIT-STOP with the wrong reason ("no `systemctl stop` of it").

The other reads the drain path does after the fact (`/proc/<pid>/environ`, `cwd`, `exe`, the fallbacks of
the parent image in `parent_image.rs`) share the same lag. They are out of scope here and keep the
current behaviour; the executed image itself is already read authoritatively in the probe.

## Decision

**Read the argument block in the `sched_process_exec` probe, as a head window and a tail window plus
its total length, and keep the `/proc` read as the fallback when the probe read is not available.**

- The probe is a raw tracepoint that receives the `task_struct *` and the `linux_binprm *`; userspace
  derives member offsets from the kernel's BTF and hands them to the probe. The argument block is
  `mm->arg_start .. mm->arg_end`, so the three new members are `task_struct.mm`, `mm_struct.arg_start` and
  `mm_struct.arg_end`.
- **What is captured, at the exec.** The total length of the block (`arg_end - arg_start`), then up to
  `ARGV_WINDOW_BYTES` = 1,024 bytes of it: all of it when it fits, otherwise the first 768 bytes (the head)
  and the last 256 bytes (the tail, read from `arg_end - 256`). Each read is one clamped
  `bpf_probe_read_user_buf` call into a fixed buffer, the pattern the probe already uses for the DNS and
  TLS payloads (`ebpf/src/main.rs`: "the length is clamped first so the verifier sees an upper bound, and
  it is one helper call, not a byte loop"). A variable-length read needs the same pre-clamp on the 5.14
  verifier; the verifier outcome is **not verified**.
- **Why a tail as well as a head.** A head-only capture lets a process pad its arguments past the window,
  put the payload at the end and exit within milliseconds: the tail is lost and nothing can be read later,
  so padding would always beat the race. The tail window removes that form for a command line that is long
  but not adversarial and for the simplest padding. It does **not** close the adversarial case: a payload in
  the middle of a block padded by 768 bytes in front and 256 behind is still omitted. For that case the
  defence is the flag and the rule below, not the windows.
- **One flag, one number, a truth table.** `cmdline_truncated` has one meaning: *the sensor knows that some
  bytes of the argument block were not captured*. A new `argv_omitted_bytes: Option<u32>` says how many:
  `Some(n)` is a known count (0 when the block was captured whole), `None` is unknown. The two are
  consistent: the flag is true exactly when `argv_omitted_bytes` is `Some(n)` with `n > 0`, or when #1116's
  capture budget (`ARGV_CAPTURE_BUDGET`, 32 KiB, not merged) cut the command line read from `/proc`
  (`None`: the size of what the cut dropped is not measured).

  | situation | `argv` / `cmdline` | `cmdline_truncated` | `argv_omitted_bytes` |
  | --- | --- | --- | --- |
  | probe read ok, block <= 1,024 B | the whole block | false | `Some(0)` |
  | probe read ok, block > 1,024 B | head and tail | true | `Some(total - 1,024)` |
  | head read ok, tail read fails (`-EFAULT`) | head only | true | `Some(total - head)` |
  | head read fails, or offsets unresolved: `/proc` fallback, process alive | what `/proc` gives | true only if the 32 KiB budget cut it | `Some(0)` when whole, else `None` |
  | the same, process already gone | empty | false | `None` |

  The probe window is always 1 KiB and the budget applies to the `/proc` read, so a total cannot tell which
  of the two cut; the flag does not try to. `None` is the honest value when the sensor saw nothing, and a
  rule must not read it as "complete". The last row is not flagged either, so the rule below cannot see an
  exec whose argv was never read at all; counting those (an "argv unknown" counter) is not part of this
  decision.
- **A rule on the flag is part of this work.** An exec whose argument block exceeds what was captured is
  itself evidence. How rare a benign one is: in #1112's sample of 3,451 execs the p99.9 is 347 bytes and the
  maximum 1,661, so at most 3 of them exceed 1 KiB; in 1,592 execs with a command line from the lab runs
  of 2026-11-03 (Fedora and Rocky) none exceeds 1 KiB (maximum 662 bytes). A stateless rule, **Low**, on
  `cmdline_truncated` with `argv_omitted_bytes = Some(n > 0)` lands with the probe change, the omitted length
  in its message; the technique id is chosen at implementation. The severity is fixed here from those two
  samples. Neither sample is committed in the repository (they are figures from #1112 and from lab captures
  that are not in the tree), both are small and from lab hosts, and they were not re-derived for this ADR.
- **What userspace builds, and what consumers read.** `argv` holds the tokens of the head and of the tail,
  in order. A token cut by a window edge is **kept as a partial token** with the bytes that were read: the
  last token of the head, and the first token of the tail (the sensor cannot tell whether the tail starts on a
  token boundary, so it is treated as partial when the block is over the window). The head and the tail stay
  separate tokens, never fused at the join. This matters for the common shape of one long argument
  (`bash -c "<script>"`, `python3 -c`, `sh -c "<blob> | base64 -d | sh"`): dropping the cut tokens would leave
  `cmdline` as `bash -c` and blind the content rules to the script; keeping them gives the first 768 bytes
  of it and the last bytes. The flag and `argv_omitted_bytes` already say that the argument is incomplete, and
  the count stays `total - 1,024` because the visible bytes of a partial token are not counted as omitted.
  Reading the `/proc` argument of a still-living process instead, when the block is over the window, is not
  retained: it reintroduces the race and the rewrite of the region described in Consequences, and the probe
  read is the exec-time one. `cmdline` stays the tokens joined by
  one space, **with no marker in it**: the loss is carried by the flag and the number, which a process cannot
  forge by writing a marker string into its own arguments. Argument strings cannot contain a NUL, so the
  windows split cleanly on NUL; an empty argument stays an empty token. The consumers of `cmdline` (the
  `base64` rule, the Sigma content, the ML command-line features) therefore read the same kind of string as
  today, a shorter one for a long command line; nothing in them changes. Whether a feature should also read
  the flag is a question for the ML parity work, not decided here.
- **Schema.** `argv_omitted_bytes` is a field of `ExecEvent`, so a `schema` change: additive and defaulted (an
  old event has none), the next free `SCHEMA_VERSION` when it lands (each schema PR takes the number after `main`'s at merge time), golden fixtures, and the shared
  fixtures of `crates/ml` and `ml/` updated in the same change (CLAUDE.md). The other platforms fill it with
  what their sensor knows, and it is not "unchanged" for them. Windows does not take the command line from the
  ETW event: it reads it from the target's PEB after the fact (`read_process_cmdline`,
  `crates/sensors/windows/etw/src/providers.rs:183`, `winapi.rs:61`), and falls back to the image path when
  the read fails, so it has the same race and no way to know that bytes were lost: `None`. macOS gets
  `argv_truncated` from Endpoint Security as a count of arguments, not bytes
  (`endpoint-security/src/ffi.rs:180`), and `normalize.rs:127` drops it today: it can set the flag from that,
  with `None` for the omitted bytes. Exact values are fixed in the schema change; whether Windows should get
  its own capture fix is out of scope.
- **The variable-length record is a new parser of attacker-influenced bytes.** The drain today reads a
  fixed-size `ExecEvent`. A record whose length depends on lengths carried inside it must be validated
  against the record size (head and tail lengths each within the window, their sum at most 1,024, the
  record at least the fixed part plus them; a record that fails is dropped and counted, never read past its
  end), and lands with a never-panic robustness suite in the crate's `tests/` and a fuzz target, like the
  other byte parsers (CLAUDE.md). This is a condition of the change, not a follow-up.
- **Wire and ring.** The exec record is `size_of::<ExecEvent>()` = 360 bytes today (a figure recomputed in review; no test in the
  repo asserts it, so it is re-measured with the rest), and `EXEC_EVENTS` is 256
  KiB: about 712 records once the 8-byte ring header is counted. A fixed 1,024-byte buffer in every record
  would make it about 1,400 bytes and the ring about 188 records, 3.8 times fewer, so a storm would shed
  sooner and a shed exec is gone. The decision is therefore a **variable-length record**: the fixed part
  stays where it is, `argv_omitted_bytes` and the two lengths are added to it, and only the bytes actually
  read follow (`output` of a slice of the scratch up to the head and tail lengths, the length clamped for the
  verifier). A typical record then grows by the command line itself (about 100 to 350 bytes) and the ring is
  raised to **512 KiB**, which keeps about the current capacity or better. If the 5.14 verifier refuses the
  variable `output`, the fallback is the fixed buffer with the ring raised to 512 KiB: about 376 records
  (524,288 / 1,392). `WIRE_VERSION` is bumped, and the per-CPU scratch grows by 1 KiB per CPU. A larger ring
  also holds a longer backlog before it sheds, and the backlog is the drain lag that the other drain-time
  reads (`environ`, `cwd`, `exe`, the parent image) suffer from: the drain lag at 256 and at 512 KiB, idle
  and loaded, is measured in the lab before the size is fixed.
- **Failure path.** `bpf_probe_read_user_buf` fails (`-EFAULT`) on a page that is not resident. The argument
  pages were written into the new stack by `execve` itself (`copy_strings`) and `create_elf_tables` sets
  `arg_start`/`arg_end` before the exec returns, so they should be resident when the tracepoint fires; this
  is from reading the kernel, not verified. A failed read gives a zero length for that window (a partial
  failure keeps the other window, see the table) and userspace falls back to the `/proc` read for the
  rest, as today.
- **Fallback when the offsets cannot be resolved.** The three members go through the **optional** loader path,
  like the `inode_setattr` offsets (`read_inode_setattr_offsets`, `ebpf.rs`), not through
  `read_scheduler_field_offsets`, whose failure stops the sensor ("could not read required fields from kernel
  BTF"). A kernel where they cannot be resolved loads the probe with the argument read disabled, logs a
  warning, and keeps today's `/proc` behaviour (the fallback rows of the table); a test with a BTF that lacks
  `arg_start` must show the sensor still starting. A kernel without `/sys/kernel/btf/vmlinux` already cannot
  run the sensor.

### Rejected

- **Keep `/proc` and retry or read faster.** The result depends on the drain latency and the process
  lifetime; neither can be controlled from the drain thread. Measured above, including idle.
- **Read `argv` at `sys_enter_execve`** (the `execsnoop` way). The syscall can fail after that point and the
  exec is not yet the process's own, so an exec event would have to be paired with a later one, and
  `execveat`, scripts and `fexecve` need their own care. `sched_process_exec` is the right moment and has the
  BTF offset mechanism.
- **`task_work` to read `/proc` from the probe.** Not available on the 5.14 kernels in the lab matrix.
- **A head-only capture.** Padding then hides the payload every time, see above.
- **A fixed 1 KiB buffer in every record.** It divides the ring capacity by about 3.8 for a sample whose
  p99.9 is 347 bytes.
- **A marker such as `…[N bytes omitted]…` inside `cmdline`.** A process can write the same text, with a
  number it chooses, into its own arguments, and it changes what the rules and the ML features read.
- **A digest of the omitted middle in the probe.** It would make an omitted middle comparable between
  execs but costs a hash of up to 32 KiB in the probe on a pre-6.6 verifier; not needed for the rule.
- **Making every rule tolerate an empty `argv`.** Each rule would be blind to the commands it exists to catch;
  the rules cannot tell "empty because short-lived" from "empty because there were no arguments".

## Consequences

- Rules reading a command line (`SECURITY-TOOL-STOP`, the stop-explained joins of #1102, `base64`, the Sigma
  content, the ML command-line features) should see the command line of short-lived processes, and the end
  of a long one. The exec path of #1102 should stop mislabelling most `systemctl stop`.
- `cmdline_truncated` and `argv_omitted_bytes` say what was not seen, also for a process that exited, and
  `None` says the sensor saw nothing. A process that pads its block should raise a Low rule instead of
  silently losing its middle; that depends on the rule landing with the probe change.
- A process can rewrite its own argument region (`PR_SET_MM_ARG_*`, or writing through `arg_start`) between
  the exec and a later `/proc` read. The head and the tail read in the probe are exec-time; the `/proc`
  read is not, and is used only on the fallback rows of the table.
- Cost: the record grows by the command line actually read and the ring doubles to 512 KiB, one or two more
  helper calls per exec, three more BTF members that must resolve, a `WIRE_VERSION` bump and a `schema`
  bump, a new parser with its own tests. The ring is shed and counted under pressure as today; the capacity
  figures above are to be re-measured.
- The offsets are the same width on LP64, so aarch64 is a low risk, but the lab matrix is x86 and aarch64
  is not verified.

## Not verified, to settle in the lab before this is built on

- That `mm->arg_start` and `arg_end` are set when `sched_process_exec` fires, on 5.14 and on 7.2: by reading
  the kernel (`create_elf_tables`) they should be; binary formats other than ELF and scripts were not
  checked. How `arg_start`/`arg_end` sit in `mm_struct`'s BTF was not checked either.
- The verifier cost on the 5.14 build of the probe and on the largest existing exec path, including the
  variable-length `output`.
- The ring drops and the drain lag under the load of the #1118 measurement (300 `true`, 100 `sleep 0.3`, 100
  `sudo -n systemctl is-active auditd`, idle and with one `yes` per vCPU), at 256 and at 512 KiB; the target
  is 0 % empty for `true`, `sudo` and `systemctl`, idle and loaded, with no more ring drops than today.
- The rate of benign execs above 1 KiB on a larger and more varied sample than the two above, which can move
  the severity of the rule.
