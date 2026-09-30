# ADR-0013: Agent local configuration — TOML file, layered discovery, fail-fast validation

- **Status**: proposed
- **Date**: 2026-09-18

## Context

Issue #19 asks for `crates/config` — the crate through which the agent,
watchdog, and CLI read their local per-install configuration. This is
distinct from `policy` (ADR-0010 / ADR-0011): policy is versioned, signed,
distributed by the control plane, and applies at runtime; local configuration
answers a different set of questions and lives on a different lifecycle.

Local configuration answers:

- **Where** the agent connects (control plane endpoint, mTLS certificates
  paths, fallback offline mode).
- **Where** it logs (path, rotation, verbosity default).
- **Where** it stores its state (spool directory, cache, model registry).
- **How** it binds its IPC (Unix socket path or Windows named pipe).
- **What** resource budgets it enforces at boot (max spool size, thread
  pool sizing).

None of this changes at runtime under normal operation. It is set once at
install time, read once at startup by every binary that needs it, and
survives across policy updates from the control plane. A single file per
install, on disk, is the right shape.

Three binaries need to read the same configuration through this crate,
consistently: `agent` (the main daemon), `watchdog` (supervisor), and
`cli` (admin tool). Any binary parsing its own dialect defeats the purpose.

The interaction with `policy` needs to be spelled out: this local
configuration file **may include the `SAFETY_CRITICAL_PATHS` list**
introduced in ADR-0011 (v1 implementation choice: hardcoded parser list, but
the paths themselves can be extended via the local config file for lab
overrides). Which means: a parsing bug in the local config file that
silently coerces a value is exactly the same class of bug as a partial
override of a safety-critical policy section, with the same consequence
(silent disabling of a security control). The format choice must reflect
this stake.

## Decision

### 1. Format: TOML

The configuration file is written in TOML.

Rationale, per the 2026-09-18 discussion with @old-dov: the file may carry
values that gate security controls (safety-critical paths from ADR-0011,
verdict-tier response allowlists once M6 lands). TOML is strict about
types (no implicit coercion, no `no`/`off`/`on` → boolean; no `1.20` →
`1.2` float truncation), which eliminates a class of silent-misconfig bugs
that YAML would introduce. TOML is also the native format of the Rust
ecosystem (`Cargo.toml`), so parsing depends on `toml` (already in the
dependency graph via `cargo`), and parse error messages are familiar to
every reviewer.

The `lab/scenarios/*.yaml` files stay in YAML: they are test fixtures with
a completely different public (scenario authors, CI replay), different
threat model (a broken scenario file fails CI immediately, not silently in
prod), and no shared-format constraint applies.

### 2. Default discovery path (per OS)

The agent looks for its configuration file at:

| OS      | Default path                                           |
|---------|--------------------------------------------------------|
| Linux   | `/etc/synthaea/agent.toml`                             |
| Windows | `C:\ProgramData\Synthaea\agent.toml`                   |
| macOS   | `/Library/Application Support/Synthaea/agent.toml`     |

These are the system-wide, machine-scope locations that a service running as
`root` / `LocalSystem` / launchd daemon can read consistently. Windows
`%APPDATA%` is explicitly rejected as a default: it is user-scoped and
invisible to a `LocalSystem` service (its `%APPDATA%` resolves to
`C:\Windows\system32\config\systemprofile\`, invisible to operators).

The parent directory (`/etc/synthaea/`, `C:\ProgramData\Synthaea\`,
`/Library/Application Support/Synthaea/`) is a **directory**, not a bare
file, so future companion files (per-install certificates in `certs/`,
cached policy fallback in `policy.toml`, drop-in overrides in
`overrides.d/*.toml`) can land beside `agent.toml` without a naming
migration.

### 3. Discovery order

Layered, highest priority first:

1. `--config <path>` on the command line, if given
2. `SYNTHAEA_CONFIG` environment variable, if set
3. Default OS path from Decision 2

Exactly one file is loaded per binary invocation. No merging across
locations (the fear-your-config rule from ADR-0010/0011 applies here too:
a merged effective config is harder to audit than a single explicit file).

### 4. Per-field environment overrides

Individual configuration fields can be overridden by environment variables
prefixed `SYNTHAEA_` (e.g. `SYNTHAEA_LOG_LEVEL=debug`,
`SYNTHAEA_SERVER_URL=https://cp.example`). Overrides apply after the file is
loaded and validated; overridden values re-validate before use. Precedence:
env override > file value. This matches the operator-familiar 12-factor
pattern without forcing full env-based configuration (files stay the
canonical, auditable source).

### 5. Missing configuration: fail-fast with instructions

If the discovery process finds no file (no `--config`, no
`SYNTHAEA_CONFIG`, no file at the default OS path), the binary refuses to
start with an error message that names:

- The exact paths that were searched, in discovery order
- The command to generate a default config template (`cli config init`,
  introduced with `crates/cli`)
- A pointer to the operator documentation

No default in-memory config is silently constructed at boot. An agent
running with "some defaults it made up" is a silent-misconfig source
worse than a hard fail at install time. The default template exists as a
committed file (`crates/config/data/default-agent.toml`), documented and
version-tracked; it is not generated at runtime from Rust literals.

### 6. Reload semantics: restart-only for v1

Configuration changes take effect on the next restart of the binary that
reads them (`systemctl restart synthaea-agent`, `Restart-Service` on
Windows, `launchctl kickstart` on macOS). No SIGHUP handling, no fsnotify
watch. Reasoning: policy changes (the runtime-mutable part) go through
the `policy` crate on their own; local configuration is set-and-forget by
design. Runtime reload without atomic validation is the source of "config
looked fine, then the agent silently degraded" bugs. Deferred for v2 if a
real operator pain emerges.

### 7. Secrets: external references only

Secrets (mTLS private key passphrase, API tokens) are **never** stored
in cleartext in the configuration file. The file carries **references** to
external providers:

- `envvar:SYNTHAEA_MTLS_PASSPHRASE` — resolved from process environment at
  load
- `file:/etc/synthaea/certs/mtls.key.pass` — resolved from a separately-
  permissioned file (typically `0600 root:root` on Linux, ACL-locked to
  `LocalSystem` on Windows)

Any string field whose schema declares it as a secret is validated at
load: if it does not start with a supported provider prefix, the load
fails with an explicit error, not a silent "field looks like a literal
secret". Secret providers themselves (envvar, file) are the extensible
list; adding new ones is an implementation change, not a schema change.

### 8. Validation: at-load, fail-fast, precise errors

Configuration is validated once, at load time, before any binary logic
runs. Errors carry:

- Field path (`server.control_plane_url`, `sensors.linux_ebpf.spool_max_mb`)
- Expected type and constraint
- The offending value

The binary refuses to start on any validation failure. No partial-config
mode. Consistent with the fail-fast principle in Decision 5.

### 9. Interaction with `policy`

`config` is loaded first at boot; it carries the control plane endpoint
and offline-mode fallback. `policy` is loaded second (either from the
control plane if reachable, or from a `config`-designated on-disk cache
for offline mode). The two crates never bundle: a change to policy shape
does not require a config schema change, and vice-versa.

The `SAFETY_CRITICAL_PATHS` list from ADR-0011 stays hardcoded in the
parser for v1 as ADR-0011's Decision 3 already specifies; local
configuration does not extend it. Migration from hardcoded to
config-extensible or schema-declared is what ADR-0011's Deferred section
already reserves for a dedicated future ADR triggered by real operator
or integrator pain — this ADR does not preempt that decision.

### Amendment: the optional `[updates]` section (issue #30)

`[updates] ring` assigns the install to a content ring (ADR-0016). It is the one
section that may be absent, added as an additive `#[serde(default)]` field, so it
needs no `schema_version` bump and existing files keep loading. The Decision 5
rule still holds where it matters: there is **no default ring**. An absent ring
means unassigned, and `agent apply-content-manifest` then refuses to run without
`--ring`, because an agent landing in `prod` by omission would bypass the canary
rollout. A value outside `canary_0`/`canary_1`/`canary_2`/`prod` fails validation
with `updates.ring` named.

## Consequences

- **Three binaries, one source of truth.** `agent`, `watchdog`, and `cli`
  all read via `crates/config`; no binary parses its own dialect.
- **Two file formats live in the repo without conflict**: TOML for
  live-config (this crate), YAML for lab scenarios (test fixtures). The
  cost is accepted with explicit rationale (different public, different
  threat model).
- **The default OS paths are consistent with EDR industry conventions**
  (`/etc/<name>/`, `C:\ProgramData\<name>\`), so operators moving from
  Wazuh, CrowdStrike, SentinelOne, or Windows Defender find the paths
  where they expect them.
- **Fail-fast at boot removes an entire class of silent-degradation bugs**
  (agent running on invented defaults) at the cost of forcing an install
  step. Acceptable trade for an EDR agent.
- **Secrets never travel in the config file itself** — a leaked config
  file is not a credential leak. Operators own the separate secret
  provisioning (envvar / permissioned file).

## Deferred

- **Runtime reload** (SIGHUP / fsnotify / atomic swap). If a real
  operational need shows up (e.g. mid-shift log-level bump without agent
  restart), earns its own ADR with a validated hot-reload path.
- **Configuration schema versioning + migration**. The v1 schema is
  version-tagged (`schema_version = 1` at the top of every config file),
  but the migration story between v1 and a hypothetical v2 is deferred
  to when v2 actually needs to exist. Same pattern as ADR-0009 model
  record and ADR-0010 policy schema.
- **Additional secret providers** (HashiCorp Vault, AWS Secrets Manager,
  Windows Credential Store). Extensible list at implementation level, no
  ADR needed until an operator asks.
- **Config-driven `crates/config/data/default-agent.toml` generator**.
  For v1, the default is a hand-written committed file; if it drifts from
  the schema, CI catches it. A generator earns an ADR when the file grows
  beyond hand-maintenance.

## References

- Issue #19 — the parent issue for this ADR.
- ADR-0010 (PR #225 merged 2026-09-18) — policy model, from which this ADR
  reuses the "fail-fast, no silent defaults" discipline.
- ADR-0011 (PR #231 merged 2026-09-18) — safety-critical override
  granularity; its Decision 3 (hardcoded parser-side list) stands
  unchanged after this ADR (see Decision 9), and its Deferred item on
  migration to extensible declaration remains reserved for a future
  dedicated ADR.
- Discord discussion 2026-09-18 (@old-dov, @Sollykhan) — the TOML vs YAML
  trancher with its public/usage argumentation.
