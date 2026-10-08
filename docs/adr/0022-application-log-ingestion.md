# ADR-0022: Application log ingestion — what the agent reads, how, and what leaves the host

- **Status**: accepted (2026-10-07)
- **Date**: 2026-10-01

## Context

Issue #478 asked how far detection should reach into web and database services
(Apache, nginx, php-fpm, MySQL/MariaDB, PostgreSQL). It proposed three levels. Level 1,
rules on the telemetry the agent already has, is on `main`: a service spawning a shell,
a webshell dropped under the web root, `mysqld` writing outside its data directory, an
outbound connection from a service account to an unusual port. Level 3, instrumenting
`mysqld` with uprobes, stays out (symbols change between versions, the cost lands on the
database server, and it would see every client query).

This ADR is the decision Level 2 needs before any code: ingesting the services' own
logs. Level 1 only sees what a successful attack does to the machine. It cannot see the
attempt, and it cannot tell "this request reached a webshell" from "a shell happened to
start". A log line carries what the endpoint sensors do not: the request, its status,
the client, the failed login. Joined to the exec, file and network events the agent
already has, a request followed seconds later by a shell spawned from the web server is
one case instead of two unrelated alerts.

The four open questions from #478 are parsing, volume, personal data, and where to
detect. What the repository already settles, and therefore bounds the answers:

- **A log source already exists, and it is allowlisted.** `sensor-linux-journal` tails
  `journalctl -o json` and "never ships the whole journal" (crate doc): only
  authentication and unit-lifecycle records are classified, with a persisted cursor
  across restarts (#321). SSH and sudo records already become `AuthEvent`s.
- **The spool is one shared, small, bounded queue.** `store::EventSpool` has a single
  byte cap and, when it is hit, deletes the oldest segments; the loss is counted and
  reaches the health beacon as `spool_dropped`. It has no per-source accounting, so a
  noisy source evicts every other source's telemetry, including process events. The cap
  the upload path applies today is a constant, 64 MiB (`SPOOL_MAX_BYTES` in
  `agent/src/upload.rs`). The `storage.spool_max_mb` value in the local configuration
  (4096 by default, validated at load) is not read by the agent code I checked, so it
  does not raise that cap. The same gap is tracked as #604; this ADR does not fix it
  and the two should be handled together.
- **Redaction has a precedent and an invariant.** ADR-0018 redacts URL credentials
  in the agent, at the sink boundary, unconditionally and only credentials, and says a
  future producer carrying a URL "must not add a second redaction path". The raw URL
  exists only in process memory between the producer and the wrapper. ADR-0018 and its
  `agent/src/redact.rs` are on `main` (#550). The access-log wiring (#478) applies the
  same `redact::redact_event` to an `HttpRequest`'s evidence value, in
  `log_sources::deliver`, the one place an access-log event leaves that module.
  `policy::RedactionPolicy` has one flag, off by default, and no policy reaches the agent
  at runtime yet (ADR-0010).
- **Allowlist plus counters, and the local-versus-policy split.** ADR-0006 decided that
  which channels are on is policy, that per-source counters exist, and that sensors
  cannot read `policy` directly. ADR-0013 decided that per-install facts (paths,
  endpoints) are local configuration with fail-fast validation.
- **Detection layers.** `docs/detection/layers.md` puts rules and the correlator on the
  device (works offline, verdicts in milliseconds) and cross-endpoint correlation on the
  server, and says cloud detection "is never an excuse to thin layers 1–4/6".
- **Loud failure over silent failure.** The Sigma engine rejects a rule it cannot
  evaluate at load time rather than never matching (#11).
- **The privilege is already there.** The packaged unit (#583, ADR-0014 amendment) runs
  the agent as `synthaea` with `CAP_DAC_READ_SEARCH`, which bypasses file read permission
  checks. Web and database logs are typically readable only by root and an admin group.
  This was not exercised against a real log file.

One more fact shapes the parser. The content of a log line is chosen by whoever sent the
request. A URL, a `User-Agent` or a username can carry quotes, spaces and escape
sequences meant to shift field boundaries, and request lines can be as long as the server
allows (Apache's `LimitRequestLine` is 8190 bytes).

## Decision

### 1. Sources in v1, declared by the operator

- Web **access logs** in Apache `common` and `combined` and nginx `combined` formats.
- The **MySQL/MariaDB error log**, for failed logins. Two parsers selected by an explicit
  `kind`, no auto-detection between them.
- Sources are declared in the agent's local configuration (a `[logs]` table in
  `crates/config`, per ADR-0013: path, `kind`, format preset), not discovered. Which
  sources are active and the detection thresholds are policy, once policy reaches the
  agent (ADR-0006's split).
- **Not in v1:** PostgreSQL (`log_line_prefix` is operator-defined, so there is no
  preset to be right about; revisit with a configurable prefix), JSON `LogFormat`,
  free-form regular expressions from configuration, container logs, php-fpm logs (its
  errors reach files or the journal and can use the journal allowlist later).

### 2. Parsing: fixed presets, a quote-aware tokenizer, visible failure

- A preset per format, parsed by a tokenizer that understands quoted fields and
  escapes, not by splitting on spaces. No user-supplied pattern in v1: it removes the
  class of configuration where a custom field such as a cookie or `Authorization` header
  ends up in an event.
- Lines longer than a fixed cap (8 KiB) are truncated and flagged, never buffered whole.
- A line that does not parse is **counted and sampled, never silently skipped**. A
  source whose failure ratio over a window crosses a threshold raises a health event
  ("log source misparsing"), because a site with a custom `LogFormat` would otherwise
  leave the sensor blind while it looks healthy.
- Rotation is handled by file identity, not only by path (rename-and-recreate and
  copy-truncate), with a persisted position per source, as the journal cursor does (#321).

### 3. Volume: filter and aggregate at the agent, never one event per request

- No per-request event. The agent emits:
  1. an event for a request that matches a detection signature (a small fixed set:
     path traversal, SQL injection markers, known scanner user agents, webshell-like
     paths and parameters, and a repeated authentication failure);
  2. one summary event per source per window (60 s): request count, 4xx and 5xx counts,
     distinct clients, and the top clients by failure count;
  3. for MySQL/MariaDB failed logins, the existing `AuthEvent` (a failure, the target
     user, the source address), not a new type.
- A per-source emission rate cap with a drop counter (ADR-0006's counter pattern), so a
  flood cannot fill the shared spool. The reason is the spool fact above: at one event
  per request, a site doing 10 requests per second produces about 860,000 events a day
  from a single source, into a 64 MiB queue that evicts oldest-first across all sources.
- Rejected: shipping raw lines to the server (raw volume, and it moves the personal-data
  problem to the server instead of solving it); sampling (an attacker's few requests are
  exactly what sampling drops).

### 4. Personal data: detect on the raw line in memory, emit the minimum

Three kinds of data appear: client addresses, URL and query content, and account names.

- **Same invariant as ADR-0018.** The raw parsed line exists only in process memory. A
  signature is evaluated on it. What leaves is built afterwards.
- **URLs.** The path stays. Query parameter names stay. Values are dropped, **except
  the value of the parameter a signature matched**, truncated to 128 characters and
  passed through ADR-0018's credential redaction. SQL injection and traversal evidence is
  in the value, so redacting every value (what `pii_scrub_enabled` would do) would
  remove the signal; keeping every value would ship tokens and identifiers. This reuses
  ADR-0018's function; there is no second redaction path.
- **User agent.** Matched locally. Only the name of the matched tool is emitted
  (`sqlmap`, `nikto`), not the string.
- **Client address.** Kept on signature events and in the per-window top clients,
  because without it neither a responder nor a server-side correlation has anything to
  act on. Not hashed in v1. It is personal data; Jean signed off on
  keeping it in clear on 2026-10-02 (see Decisions on the open questions).
- **Account names.** MySQL/MariaDB login names are kept. They are the signal for a
  brute-force case. Passwords never appear in these logs.
- Because v1 has no user-defined formats, no field the presets do not name (cookies,
  authorization headers) can reach an event.

### 5. Where to detect: both, split by the shape of the data

- **On the agent:** per-line signatures and short-window counters, as native `rules`
  like Level 1, not Sigma (the Sigma subset maps only to `ExecEvent` fields and
  `condition: selection`, and has no web-server log source; extending it is its own
  decision). This keeps detection working offline and lets the correlator join a request
  to the exec, file and network events the agent already holds (layer 6), which is the
  reason to read logs on the endpoint at all.
- **On the server:** cross-host questions, from the summary events only: the same client
  hitting several hosts, a fleet-wide scan (layer 7). The server never receives raw log
  lines.

### 6. Event representation

- A new `HttpRequest` event for signature matches, and a summary event for the window
  counters, in `schema` (additive: a `SCHEMA_VERSION` bump and a new fixture directory).
  Failed database logins reuse `AuthEvent`, following ADR-0005's shared type.
  Nothing fits a log record in the existing variants, and bending `FileOpenEvent` as the
  journal persistence tracker does would be a worse approximation here than there. The
  exact fields are designed in the implementing change; this ADR fixes only that HTTP
  requests get their own variant.

### 7. Not in scope

Raw log retention or forensics (an attacker who controls the web application can write
to these logs, and one with root can erase them: a detection input, not an archive);
blocking or response to a request (the response crate is separate); auto-discovery of
log paths; Level 3.

## Consequences

- **Easier.** The most useful correlation for the services Level 1 covers becomes
  possible: request, then process, in one case. The data volume is bounded by
  construction (signature events plus one summary per window), and the same redaction
  function covers it.
- **Harder.** A parser is attack surface fed by attacker-controlled text, so each
  preset gets a fuzz target, as the audit and netlink parsers have (`fuzz/`). Each
  preset is a maintained format. Sites with a custom `LogFormat` are covered only through
  the "misparsing" health event and a follow-up for JSON, not silently.
- **Reading logs needs no new capability** if `CAP_DAC_READ_SEARCH` behaves as
  documented on a real host. That is an assumption to check, and the ADR-0014 table
  should name log files as a reason for that capability when the first reader lands.
- **Risks accepted.** A request that never reaches the logging module (a crash, a log
  level that omits it) is invisible. An attacker with root can stop or truncate a log;
  detecting that a source went quiet is ambiguous for a site with little traffic and is
  not alerted on in v1 rather than faked with a canary.
- **Validation before this becomes accepted.** Lab scenarios under `lab/scenarios/`
  (Level 1 left that gap) on real Apache, nginx and MariaDB logs from a lab VM: a webshell
  request followed by a shell spawn, a traversal and an injection attempt, a failed-login
  burst, plus a custom `LogFormat` to exercise the misparsing event.

## Decisions on the open questions (2026-10-02, Jean)

1. **Data protection.** The client address and one truncated parameter value stay on
   signature events, in clear, with the value passed through ADR-0018's redaction. No
   pseudonymization in v1.
2. **PostgreSQL.** Deferred, as written in section 1: `log_line_prefix` is
   operator-defined, so no preset would be reliable.
3. **Priority.** Level 2 proceeds now, ahead of #456 and #555 and the remaining
   Windows sensors.
4. **Silence of a log source.** No alert in v1. A quiet site is normal, and the ADR
   does not fake a canary.

Validation, completed 2026-10-07: nginx 1.24 with the real agent (`web-webshell.sh`, earlier),
then Debian 13 (kernel 6.12.107) with Apache 2.4, PHP-FPM 8.4 and MariaDB, the agent run as
root: a webshell request followed by a shell spawned by an `apache2` parent
(`web-webshell.sh`, `FAKE_COMM=apache2`) and by a real php-fpm worker
(`web-webshell-php.sh`), both paired as T1505.003 and T1059; the evidence value of a
parameter named `password` leaves as `REDACTED`; six failed logins raise T1110 from the
MariaDB error log; a custom `LogFormat` raises `LOG-SOURCE` (`web-custom-logformat.sh`);
one `http_summary` per source. Not validated: MySQL 8 against the full agent, and a client
logged with a resolved IP.
