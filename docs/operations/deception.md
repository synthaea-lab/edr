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
