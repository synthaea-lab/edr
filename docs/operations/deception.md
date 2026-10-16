# Deception: canary files

The agent can plant decoy files ("canaries") that nothing legitimate reads and raise a
High detection when another process touches one. It is off until you name directories
(ADR-0029, issue #81).

```toml
# agent.toml
[deception]
canary_dirs = ["/srv/share", "/var/www/uploads"]   # absolute, existing, at most 16
```

Each directory gets one canary per kind (credentials, finance, config, notes). Names and
contents come from a per-install seed kept in `<state_dir>/deception/seed`, so two hosts
get different files. Every canary starts with a line saying it is a machine-generated,
inert decoy. Their modification times are seed-derived and distinct within a directory; when
neighboring files have a wide enough mtime range, the canaries are placed inside it. In an
empty directory (or one whose files all have the same or too-close timestamps), each canary
gets a different time one to 365 days in the past. On Unix, the agent also copies the
majority owner/group and permission bits from regular neighbouring files when it has permission
to do so. It logs the fields it cannot match (`owner`, `mode`, or both) once for that directory.
If the common mode would remove owner-read, the agent keeps that bit so it can verify the
canary contents, and logs `mode` as unmatched. Directories without regular neighbouring files
keep the agent's default metadata. Windows keeps the platform defaults. Remove the
`[deception]` table and restart to take them all back out.

A canary that gets deleted is planted again, with the content it had, at the next start and
within the hour while the agent runs (the deletion itself already raised a detection). A file
that was modified or replaced is never overwritten. To get rid of a decoy, take its directory
out of `canary_dirs`; deleting the file only makes it come back.

**What an uninstall leaves** (checked on `main`, Fedora 44, 2026-10-14: two installs with
different seeds, then one restarted without `[deception]`): the canaries are removed
(`canaries removed removed=4`) and so is the inventory. The `seed` file stays in
`<state_dir>/deception/` (ADR-0029). The canary directories were yours: the agent never creates a
missing one and never removes one, so an empty directory afterwards is not a residue.

## With the packaged systemd unit

The unit runs the agent as the unprivileged `synthaea` user with `ProtectSystem=strict`,
which makes everything except `ReadWritePaths` read-only. A canary directory has to be
added there **and** be writable by that user, or planting fails for it:

```
deception: planting failed here ... dir=/srv/share
```

The other directories are still planted. A drop-in (`systemctl edit synthaea-agent`):

```ini
[Service]
ReadWritePaths=/srv/share /var/www/uploads
```

```
chown synthaea /srv/share      # or a group/ACL that lets synthaea create files there
systemctl restart synthaea-agent
```

Adding a directory to `ReadWritePaths` lets the agent write there. Pick directories you
are willing to hand it, and not ones users work in: a canary belongs where nothing
legitimate reads.

## Where canaries fire

- The Linux sensor does not report read-only opens under `/tmp`, `/var/tmp`, `/dev/shm`,
  `/dev`, `/sys` and `/proc`. A canary there still fires on delete, rename and write, never
  on a read, so it will not catch reconnaissance. Place canaries elsewhere.
- **A canary touch can be missed while the host is flooded with file opens.** Detection reads
  the sensor's open events, and the kernel ring buffer drops them when it overflows
  (`ring buffer full, dropping open event` in the agent log). Measured 2026-10-14 on a 2 vCPU
  Fedora 44 VM: 20 of 20 touches alerted on a quiet host, 9 of 20 while another process read
  `/usr` and `/etc` (29,402 drops). Anyone who can generate open load can therefore hide a
  touch, and the health beacon does not count these drops, so nothing on the control plane says
  the sensor was blind. Place canaries as the first line of a defence in depth, not the only one.
- Windows and macOS plant too, but the packaged-unit notes above are Linux-only.

## Letting a known indexer or backup read the canaries

```toml
[deception]
canary_dirs = ["/srv/share"]
allow_exe = ["/usr/libexec/plocate/updatedb.plocate"]   # absolute path of the real binary
```

A process is allowed only when its executable, as the kernel reports it (`/proc/<pid>/exe`),
is on the list and the process is in the agent's mount namespace. Never the process name.

- **Use the real file, not a link**: the agent resolves symlinks at start (so
  `/usr/bin/updatedb` is compared as `updatedb.plocate` on Debian), but check
  `readlink -f` on the host rather than assume.
- **Check what your indexer really does before listing it.** plocate's `updatedb`, run as its
  real systemd service on Fedora 44 (2026-10-14), indexed the canary directory (the directory and
  its four files) and raised no detection **with and without** `allow_exe`: it reads directory
  entries and does not open the files, so there was no touch to allow. The list is for tools that
  open the files (backup agents, content indexers); this run did not exercise it.
- **A touch can wait up to half a second for the process's `exec`.** The sensor stamps an `exec`
  before the open that follows it, but the events reach the agent merged, and the open of a
  short-lived process (a `tar` started by cron, `bash -c "tar ..."`) can arrive first, after
  which `/proc` has nothing to say. With an allow list, a touch whose process is not allowed by
  what the agent knows and whose `/proc` entry names no executable is held for up to 500 ms of
  event time: an `exec` of an allowed image (the last of several: `bash`, then `tar`) drops it,
  anything else raises it when the time is up. A process `/proc` shows running another image is
  raised at once, and so is every touch when `allow_exe` is empty. At most 256 touches are held;
  beyond that they are raised at once. The ransomware reflex sees such a touch up to 500 ms
  later. Measured 2026-10-16 on the Fedora VM: a `tar` started by a real `crond` raised 12 alerts
  in 3 processes before this, none after, with `allow_exe = ["/usr/bin/tar"]`.
- **Shells and interpreters are refused** at load (`bash`, `sh`, `python3.x`, `perl`, `find`,
  `env`, ...): allowing one allows every script it runs.
- **The entry must be in a trusted system location** (`/usr`, `/opt`, ...) and must not be
  replaceable by an unprivileged user. `/opt/<app>` is often the application's own.
- **How a process is recognised.** From the `Exec` event the agent saw when it started
  (needs no privilege, so it works for a cron-started `updatedb` run by root), and otherwise
  from `/proc/<pid>/exe`. A process that was already running when the agent started, or
  whose `Exec` was shed, only has the `/proc` route, and for another user's process that needs
  `CAP_SYS_PTRACE`, which the packaged unit does not grant (ADR-0014): it is not recognised and
  still raises the detection. Add the capability in a drop-in only if you accept that trade
  (ADR-0023 makes the same one for memory scanning).
- The exec table is only as fresh as the events the agent received: a process that execs an
  allowed binary and then something else, with that second event lost, is still recognised as the
  first where the agent cannot read `/proc/<pid>/exe`. Where it can, a disagreement denies.
- A listed script (`#!`) is checked against `/proc` by its interpreter. An `env` shebang
  (`#!/usr/bin/env python3`) names `env`, so the interpreter cannot be read from the file: where
  `/proc` is readable the program it shows must sit in a trusted system location, otherwise the
  table alone decides (like any process whose `/proc` cannot be read).
- An entry whose own path is outside a trusted location (a link in `/tmp` to `/usr/bin/x`) is
  matched by its resolved path only; the agent warns at start.
- The exec event does not carry a mount namespace. Where the agent can read the process's
  namespace link and it differs from its own, the process is not allowed. Where it cannot (no
  `CAP_SYS_PTRACE` for another user's process), a local user who can create user and mount
  namespaces can bind-mount their own binary over a listed one and be recognised as it.
  Where that matters, disable unprivileged user namespaces (`user.max_user_namespaces=0`)
  (ADR-0029).
- An exec reported under a name the list does not hold (`/bin/updatedb` under usrmerge, a
  `PATH` lookup) is not refused by the table: `/proc` canonicalises it and decides, as before.
- A process in a container, a relative exec, a replaced binary (`... (deleted)`, `/proc` route)
  and a process that cannot be resolved are not allowed: the detection is raised.

## Decoy credentials

The credentials and config canaries each carry a fake token (`api-token : syn_dk_...`,
`cron_secret = syn_dk_...`) derived from the install's seed. When the agent starts it sends
the control plane the SHA-256 of each one (never the token), retrying in the background if
the server is down. A request that presents one as a bearer token to the control plane is
rejected as usual and also raises a **high** `T1552.001` detection against this agent, with
the host's name, the route and the client address, at most once a minute per token (ADR-0030).

To check it by hand with the agent running and registered, read a token from a canary and
present it to a cron route (it is refused with a 401; the detection appears in the console):

```
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $(grep -ho 'syn_dk_[0-9a-f]*' /srv/share/* | head -1)" \
  https://<control-plane>/api/cron/detect-silent-agents
```

**An upgraded host keeps its old canaries, and they carry no decoy.** `plant` never overwrites
a file, so canaries planted by a build before the decoy tokens keep their old content, and the
agent registers only the tokens it finds in the files on disk (none, for those). To get decoys
on such a host, take its directories out of `canary_dirs` and restart (the canaries are
removed), then put them back and restart. Nothing logs this case yet.

Checked 2026-10-14 against a running control plane: the decoy bearer got a `401` and one
`T1552.001` detection naming the planting agent and host; a random `syn_dk_...` bearer and a plain
random bearer got a `401` and created nothing; no detection row contained the token.

Limits: only a token presented on a route that evaluates a bearer (today the `/api/cron/*`
routes) is seen; a standalone agent plants tokens that nothing recognises; and the control
plane learns of a token only when the agent registers, so after a server database reset
decoys are recognised again once the agent restarts.
