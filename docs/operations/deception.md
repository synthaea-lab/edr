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
inert decoy. Remove the `[deception]` table and restart to take them all back out.

A canary that gets deleted is planted again, with the content it had, at the next start and
within the hour while the agent runs (the deletion itself already raised a detection). A file
that was modified or replaced is never overwritten. To get rid of a decoy, take its directory
out of `canary_dirs`; deleting the file only makes it come back.

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
- An entry whose own path is outside a trusted location (a link in `/tmp` to `/usr/bin/x`) is
  matched by its resolved path only; the agent warns at start.
- The exec route cannot see a mount namespace: a local user who can create user and mount
  namespaces can bind-mount their own binary over a listed one and be recognised as it.
  Where that matters, disable unprivileged user namespaces (`user.max_user_namespaces=0`); it
  is a limit of the exec route, not of the `/proc` one (ADR-0029).
- A process in a container, a relative exec, a replaced binary (`... (deleted)`, `/proc` route)
  and a process that cannot be resolved are not allowed: the detection is raised.
