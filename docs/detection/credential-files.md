# Credential-file reads (CREDENTIAL-READ, #377)

One rule over the file-open stream of a Unix host: `RuleState::check_credential_file_read`
(`crates/rules/src/state.rs`), with the path knowledge in `crates/rules/src/credfiles.rs`. It is
the part of the Credential Access pack (#377) that needs no new telemetry. The Windows
(T1003.001, #137) and Kerberos (T1558) rows are not here.

| Technique | Path | Alerts when the reader is |
| --- | --- | --- |
| T1003.008 | `/etc/shadow`, `/etc/gshadow`, and their `-` backups | anything outside the authentication stack |
| T1552.004 | `~/.ssh/id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` (and `_sk`) under `/home/<user>`, `/root`, `/Users/<user>` | a web or database service (or its child), or a binary run from outside the system directories |
| T1555.001 | macOS: `~/Library/Keychains/login.keychain-db` and `login.keychain`, `<device dir>/keychain-2.db`, `/Library/Keychains/System.keychain` | the same as T1552.004 |
| T1555.003 | macOS: a browser's saved logins, cookies and autofill (`Login Data`, `Cookies`, `Web Data` for Chrome, Edge, Brave and Chromium; `logins.json`, `key4.db`, `cookies.sqlite` for Firefox) under `~/Library/Application Support` | the same as T1552.004 |
| T1552.001 | `~/.aws/credentials`, `.git-credentials`, `.netrc`, `.pgpass`, `.docker/config.json`, `.kube/config`, `.azure/accessTokens.json`, two files under `.config/gcloud` | the same as T1552.004 |

Severity is Medium for all three and is not calibrated. A write-only open is never an alert; a
read-write open is. One alert per (pid, kind of file) per five minutes, from a sliding
timestamp counter in a bounded map (no unbounded state). The message carries the pid, the
process name and the path the process asked for, never a command line or file content.

## Why the readers are decided differently

The shadow files have a short, fixed list of legitimate readers: `login`, `sshd`, `sudo`, `su`,
the `shadow-utils` tools, the PAM helpers (`unix_chkpwd`), cron's account check, the display
managers' session workers (`credfiles::AUTH_STACK`). Anything else that opens them alerts.

A home credential file has no such list: `python3` with `boto3`, `terraform`, `kubectl`, `git`
and `ssh` all read their own, from `/usr/bin`. Alerting on every reader would alert on every
`aws` call. So the rule asks whether the reader is *unexpected in a way the telemetry can
prove*: a web or database service (resolved from the exec table, since `comm` is the thread's
name, `one_connection` for a `mysqld` worker) or a child of one, or an image the sensor reports
outside `/usr`, `/bin`, `/sbin`, `/lib`, `/opt`. A process with no known image and no service
parent never alerts: a sensor gap is not evidence.

An exclusion by name is only as good as the name. For the shadow files the **exec-time image**
decides, not `comm`: an `sshd` copied to `/tmp` is not excluded, and a script interpreter that
sets its own name to `sshd` is not either. Only a pid with no known image falls back to the name,
as `policy::name_exclusion_applies` does everywhere else. A child that forked without an exec (an
older `sshd`'s privilege-separated child) inherits its parent's image.

## What it cannot see

- **A relative path.** The sensor reports the raw `openat` argument: `cd /etc && cat shadow`
  opens `shadow`. A `dirfd`-relative open is the same.
- **A symlink.** `/tmp/x` pointing at `/etc/shadow` opens `/tmp/x`.
- **macOS:** `/var/root`'s keychain and browser profiles, Safari's own stores, and a profile
  directory the table does not name (Opera, Vivaldi, Arc). The ES open event carries the path and
  the open mode as POSIX flags (`sensor-macos-endpoint-security`, `open_fflag_to_flags`); whether
  the sensor's mute list drops any of these paths on a real host is not checked.
- **A credential file outside a home directory** that the table lists: a service account's home
  (`/var/lib/jenkins/.ssh`), `/etc/ssh/ssh_host_*_key`.
- **A system binary run by an intruder** against a home credential file (`cat`, `tar`, `cp`) when
  its parent is not a web or database service. The shadow rule does catch these; the home-file
  rule does not, on purpose.
- Only the aliases that normalise lexically are folded: `//`, `/./`, `/../`, and
  `/proc/<pid>/root` or `/proc/self/root`.

## False positives, assessed

Reasoned from what each producer does, **not measured on a live host** (no lab run for this
rule). The first alerts of a real fleet are the calibration.

- **Shadow, expected to fire:** an administrator's `cat`/`grep`/`getent`-style read; a backup or
  integrity tool (`tar`, `rsync`, `borg`, `rpm -V`, `debsums`, AIDE, a vulnerability scanner); a
  PAM service the list lacks (`vsftpd`, `saslauthd`, a mail or FTP daemon). None is excluded: each is
  also what an attacker runs. The remedy for a PAM service is to add its image name to
  `AUTH_STACK`, with the dated observation.
- **Shadow, expected quiet:** an interactive login, `sudo`, `passwd`, package scriptlets that call
  `useradd`, `systemd --user` sessions (`(sd-pam)`).
- **Home files, expected to fire:** a developer's tool installed under their home
  (`~/.local/bin`, `~/go/bin`, a virtualenv) reading its own credentials.
- **Home files, expected quiet:** the system-installed tools reading their own.
- **macOS, expected to fire:** a browser installed under `~/Applications` reading its own store; a
  backup or sync tool run from a home directory.
- **macOS, expected quiet:** the Apple daemons that read a keychain, and browsers in
  `/Applications`, because they run from the system directories. **Not observed on a Mac.** A
  system `cp` or `cat` of a keychain by an intruder is the same known miss as for the home files.

The auth-stack list and the `(sd-pam)` entry come from how PAM and `systemd` behave, not from a
captured run. Check them against a real login on a lab VM before widening the rule's severity. The
macOS rows have not run on a Mac at all.

## Tests

`crates/rules/src/tests/credfiles.rs` (regression, one per behaviour above, including the
rename and `prctl` masquerades and the bounded history) and the unit tests of the path
classifier in `credfiles.rs`.
