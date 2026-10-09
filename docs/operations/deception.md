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

Limits: only a token presented on a route that evaluates a bearer (today the `/api/cron/*`
routes) is seen; a standalone agent plants tokens that nothing recognises; and the control
plane learns of a token only when the agent registers, so after a server database reset
decoys are recognised again once the agent restarts.
