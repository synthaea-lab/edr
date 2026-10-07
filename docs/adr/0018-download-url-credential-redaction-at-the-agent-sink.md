# ADR-0018: Download-URL credential redaction at the agent's sink boundary

- **Status**: accepted
- **Date**: 2026-09-30

## Context

`FileQuarantineEvent`'s `origin_url`/`referrer_url` (#365 on Windows, from the
`Zone.Identifier` `HostUrl`/`ReferrerUrl`; #96 on macOS, from
`kMDItemWhereFroms`) are copied verbatim from what the downloading
application recorded. Often that is a bearer credential: an S3/GCS/Azure
pre-signed link, an OAuth `access_token`, a session id, a `user:pass@`
authority. Each one lands in the spool, `events.jsonl`, the server, the
T1204.002 alert message, and in lab captures that end up committed under
`lab/captures/` (#440).

The query string can also be the evidence (a campaign id, a kit's tracking
parameter), so dropping it unconditionally loses signal.

`policy::RedactionPolicy` (#299, ADR-0010) exists for "redaction at emission
time", but it holds a single `pii_scrub_enabled` flag that is off by default,
and no policy reaches the agent at runtime yet. Redaction gated on it alone
would redact nothing by default.

Where to redact is constrained too: sensor crates depend only on `schema`
(`tools/check-deps.py`), so sensor-side redaction means either the same code
in `sensor-windows` and `sensor-macos`, or a new public function in `schema`,
whose API is semi-frozen.

## Decision

**What.** Credentials are redacted unconditionally, and nothing else is:

- the userinfo (`user:pass@` → `REDACTED@`);
- the fragment (OAuth implicit-flow tokens live there);
- the value of every query parameter whose name marks it as a secret:
  exact names (`sig`, `code`, `sid`, …), name fragments (`signature`, `token`,
  `secret`, `credential`, `session`, …) and suffixes (`key`, `keyid`, and
  `auth`, which catches SharePoint/OneDrive's `tempauth` bearer token).

Parameter names stay (`X-Amz-Signature=REDACTED` still reads as "pre-signed
S3"), and so do scheme, host, path and every other parameter. Redacting *all*
query values is left to `RedactionPolicy::pii_scrub_enabled`, once policy
reaches the agent.

**Where.** In the agent, as a `RedactingSink` (`agent/src/redact.rs`) wrapped
around the sink every sensor feeds. On Windows and macOS, `agent run`,
`capture-events` and `capture-baseline` all go through
`run_windows_sensors` / `run_macos_sensors`, which is where it sits. Every
consumer, including detection, only ever sees the redacted URL.

## Consequences

- One implementation for both producers, no `schema` API change, and it sits
  in the binary: the one place that will be able to read `RedactionPolicy`
  when policy distribution lands.
- Lab captures are redacted too, since `capture-events` goes through the same
  funnel.
- Best-effort by construction. Known gaps, all probed against real download
  URLs in review (#550):
  - a secret in the path (`/dl/<token>/x.exe`), including a matrix parameter
    (`;jsessionid=`) and `;`-separated query parameters;
  - short, host-specific names, too generic for a name-only rule: Slack's
    `t=` (`xoxe-` user token), Google Drive's `at=`, Discord's `hm=`, a
    one-time `?id=`. Covering them means a host-aware table, which is a
    follow-up, not a tweak to the name lists;
  - the first parameter of an unencoded URL nested in a value
    (`?next=https://idp/cb?access_token=…` reads as `next`'s value);
  - a name whose secret part is itself percent-encoded (`%74oken`). An
    encoded separator (`Access%5FToken`) is still caught by the substring
    match.

  These URLs are written by browsers and download tools, so the goal is not
  storing benign credentials, not beating an adversary who controls the URL.
- Detection loses nothing it used: no rule reads query values, and the
  T1204.002 join keys on the path.
- The raw URL exists only in process memory between the sensor and the
  wrapper; it is never persisted or sent.
- Linux has no `FileQuarantine` producer, so it wires no `RedactingSink`. A
  future Linux producer, or any other event type that carries a URL (a DNS or
  TLS URL field, for instance), has to go through the same wrapper or extend
  it. It must not add a second redaction path.
- The Linux access-log sources (#478, ADR-0022 §4) extend `redact_event` instead:
  an `HttpRequest`'s evidence value (the one query parameter a signature matched
  on) is replaced by `REDACTED` when that parameter's *name* marks it as a secret,
  by the same name rules as a URL query, and kept otherwise since it is the
  evidence. `log_sources::deliver`, the one exit of that module, calls it. The same
  limits apply: a secret inside the value of a parameter that is not named like one
  (`?cmd=curl -H "Authorization: Bearer ..."`) is not caught.
