# Linux privilege escalation: setuid-to-root and the sudo burst (#1041)

Follow-up of #973. Two questions, one measurement: is there a low-false-positive **sudo burst** rule
(T1548.003), and what can be built over the identity-change telemetry of #266 (T1548.001)?
Measured on the Fedora 43 lab VM (kernel 7.2.9, sudo 1.9.17p2, agent of `feat/60-beacon-counters`
in `capture-events` mode), 2026-10-29. Raw events and scripts: `lab/captures/test-1041-20261029/`.
**One VM, synthetic workloads, no fleet baseline**: it shows shapes and magnitudes, not a calibrated
threshold.

## Sudo burst (T1548.003): no rule

Successful `sudo` per account, from the journal lines the agent's `AuthEvent` source reads
(`COMMAND=` lines; `PrivilegedSession`):

| Workload | Successes | Window |
| --- | --- | --- |
| quiet host: the lab user's own setup commands | 5 | 300 s |
| scripted "administrator" (2 sudo per 6 s, one uid) | 20 | 60 s |
| config-management / CI style loop (one uid, `sudo -n` per step) | 451 | 12 s (384 in the busiest 10 s) |
| one `sudo` running a 40-step install script | 1 | one sudo, many children |

Counting successes per uid cannot separate a CI runner or a deploy from anything else: the benign
case is two orders of magnitude above any threshold a human-paced attack would stay under, and an
intruder needs a handful of `sudo` calls, not hundreds. **No threshold exists that is quiet on the
CI loop and still catches something.** The shape that does discriminate is already built:
`check_sudo_success_after_failures` (#381), a success that follows failures for the same uid.
First-seen account (#376) covers the account that never used the host. Not measured: a real fleet
(M9), interactive human rates over days, `sudo -i`/`sudo su` share.

## Setuid to root (T1548.001): SETUID-ROOT-REQUEST, Low

`RuleState::on_identity_change` (`crates/rules/src/privesc.rs`, wired in the agent sink): a process
whose real uid is not 0 asks for uid 0 (`setuid(0)`, or `setresuid` with 0 in any slot), and its
exec-time image is not a measured setuid-root program at a system path. T1548.001, **Low**, one
alert per process.

What the telemetry is: the call at syscall **entry**, `meta.user` the caller's real uid, so a refused
`setuid(0)` (EPERM) and a granted one look alike. What was measured:

- Callers of "uid 0 from a non-root real uid": `sudo`, `su`, `crontab`, `sshd-session`, `sshd-auth`
  (the list in `SETUID_ROOT_PROGRAMS`).
- A non-setuid `python3` as uid 1001 (the positive case): `set_uid 0` and `set_res_uid 0 0 0`
  recorded.
- A copy of `python3` renamed `sudo` in `/tmp`: same events with `comm = sudo`. **The name is not
  evidence**, so the rule goes by the exec image (`pid_image_path`), which must be under a system
  path (`policy::name_exclusion_applies`) and named like a measured program.
- Root dropping privileges (`setuid(1001)` as root) and root's own calls: not a request.
- The other setuid programs on the image (`chage`, `chfn`, `chsh`, `gpasswd`, `mount`, `newgrp`,
  `passwd`, `pkexec`, `umount`, `unix_chkpwd`, `pam_timestamp_check`, `polkit-agent-helper-1`,
  `grub2-set-bootflag`) were run with `--version`/`--help` only and none asked for uid 0 there.
  **Their real operation was not exercised**, so `pkexec`, the polkit helper, `newuidmap` and
  container tooling may alert: the reason for Low and a provisional list.

Not covered: an exploit inside a listed binary (same request as the real one); a pid whose exec the
agent did not see (no image, silent); `setreuid`, which `IdentityChangeKind` does not carry; group
ids and `setfsuid`. Tests: `crates/rules/src/tests/privesc.rs`.
