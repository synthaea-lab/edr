# ADR-0043: The agent's observable names live in one module, and sensors are handed theirs

- **Status**: proposed
- **Date**: 2026-10-29

Issue #596. The number was the next free one when this was written (open PRs propose 0039 to
0042), so renumber on merge if another lands first.

## Context

The morph design (the private archive's ADR-0005 and `04-morph.md`) plans per-install
randomization of the agent's observable identity for milestone M4. Real EDR killers do not
analyse binaries. They hardcode names: the service, the systemd unit, the launchd label, the ETW
session prefix, the files and sockets the agent leaves on disk. The design asks for those names
to be tracked from M1, so that M4 can replace them without first having to find them.

On `main` before this ADR, the names were literals at their call sites. Some of them were spelled
in two places that had to agree:

- The watchdog and the agent each spelled `SYNTHAEA_WATCHDOG_RESTARTS`. A test in the agent
  checked the watchdog's source text so the two could not drift apart.
- The systemd unit name was spelled in the watchdog's installer, the agent's release restart and
  the packaging.
- The ETW session prefix was hardcoded in a sensor crate, and startup reaps orphan sessions by
  that prefix.

## Decision

### 1. One module: `config::identity`

Every observable name that the user-mode binaries or the leaf crates use is a constant in
`crates/config/src/identity.rs`. The agent, the watchdog and the CLI already depend on `config`,
and M4's per-install values are configuration by nature. The default config paths and the
`SYNTHAEA_*` override variables are the same kind of name. They already live in `config`
(`discovery.rs`, `load.rs`), next to the code that reads them, and they stay there.

A new observable name is added to that module and to the inventory on #596. It is never written as
a literal at its call site.

### 2. Sensors are handed their names

Sensor crates depend only on `schema`, so they cannot read `config::identity`. The agent passes a
sensor the names it leaves on the host when it constructs the sensor. The first one is
`sensor_windows::EtwNames`, which carries the session prefix and the canary file prefix. A sensor
holds no default name of its own, so it cannot quietly keep the old one.

Transport is a leaf crate and cannot depend on `config` either. It takes the `User-Agent` as an
optional field. Left unset, it sends the HTTP client's own default, which does not name the
product. The agent builds every client through one helper that sets the field. The local IPC
hello now carries only the version.

### 3. Names looked up across restarts must be stable per install

Some names are only ever looked up by prefix: startup stops every ETW session under our prefix to
reap the orphans of an unclean shutdown (#408). If M4 randomizes such a name, the value must be
persisted in the install's configuration and read back, not drawn at each start. Otherwise the
agent stops finding its own orphans. The ETW prefix is constant today; this rule binds M4.

### 4. Second spellings outside Rust are pinned by tests

Some files cannot import the constants: the packaged systemd unit and OpenRC script, and the
socket path the Swift network extension falls back to. Tests in `config::identity` check that
each of these files still carries the constant's value.

### 5. Out of scope

- Randomization itself (M4).
- The minifilter's port name, connect magic and service SID check (#508, #560). They belong to a
  signed driver and change per release, not per install, so they stay in the driver's protocol
  crate. Making them negotiable by the agent is driver work.
- The Linux sensors' names (the BPF pin directory, the journal canary identifier). They follow
  the ETW pattern in a later change and stay listed on #596 until then.

## Consequences

- M4 can work from one module plus one table instead of a repository-wide search, and a review can
  reject a new literal name by pointing at this ADR.
- The agent/watchdog environment-variable pair is now a single constant, so the source-text test
  that kept the two spellings equal is gone.
- A sensor that leaves a name on the host grows a constructor parameter. That is the price of
  keeping sensors dependent only on `schema`.
- Without a `User-Agent` set, transport identifies itself as its HTTP library. The agent always
  sets one today, so nothing changes on the wire.
