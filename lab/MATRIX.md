# Lab Machine Matrix

The canonical list of machines the lab must be able to produce, harness-independent.
Every harness (`vagrant/`, or your own) should be able to bring up any Linux row; the
Windows and macOS rows carry their own host constraints.

## Why a kernel matrix

The eBPF probes are entirely tracepoint-driven — parent lineage from `sched_process_fork`
fields (#53), the executed image from `sched_process_exec` (#111), argv from
`/proc/<pid>/cmdline` read in userspace (#152). No `task_struct`/`mm_struct` frozen
offset, no `vmlinux` BTF bindings. Every kernel row is still a genuine portability test
case — tracepoint record layout, `__data_loc` handling, BTF at load, and verifier
behaviour all drift across versions — but there is no per-kernel offset table to
regenerate any more.

| Machine | Family | Kernel | Proves |
| --- | --- | --- | --- |
| ubuntu-24.04 (primary) | Debian | 6.8 | primary dev/validation target — validated 2026-09-24 on `vagrant-hyperv/` (26/26 programs, argv + lineage with #416); inline-comm `sched_process_fork` |
| ubuntu-22.04 | Debian | 5.15 | oldest supported LTS kernel |
| debian-12 | Debian | 6.1 | Debian stable |
| debian-13 | Debian | 6.12 | newest kernel drift — validated 2026-09-24 on `vagrant-hyperv/` (26/26 programs, argv + lineage with #416); still inline-comm `sched_process_fork` (`__data_loc` first seen on alpine 6.18, #415) |
| fedora-41 | RPM | 6.11 GA, 6.17 with updates (validated on 6.17.7) | RPM family, SELinux Enforcing — validated 2026-09-30 on `vagrant-hyperv/` (`fedora41`): agent + eBPF build natively (clang/LLVM 19 + prebuilt bpf-linker), 51/51 programs, `lineage.sh` 3/3 and `argv.sh` on a `__data_loc` `sched_process_fork` (#415/#416), 0 AVC denials for the agent run from a shell (not yet under its systemd unit) |
| rocky-9 | RPM (RHEL) | 5.14 | enterprise RHEL-clone baseline; replay-only |
| arch (rolling) | pacman | 7.2 (validated 2026-09-21; moves) | rolling kernel/LLVM drift target for #53 CO-RE (#124) — beacon.sh end-to-end confirmed (T1071/T1041 fired), previously blocked on #199 |
| alpine-3.24 | musl/BusyBox | 6.18 (virt) | musl libc + BusyBox userland, not glibc (#123); `vagrant/` box (`generic/alpine319`) tracks 3.19/6.6, the newest Vagrant Cloud publishes with a virtualbox/amd64 provider — not kernel-version-sensitive for this row's purpose |
| windows-11 / windows-10 | Windows client | — | ETW sensor validation |
| windows-server | Windows server | — | ETW on server SKUs |
| macos | macOS | — | EndpointSecurity validation — real hardware or Tart/UTM; no Vagrant box |

Additions to this file are the trigger for harness updates, not the other way around.
