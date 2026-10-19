# ADR-0036: Operator notifications: signed webhooks from an outbox, on state changes

- **Status**: proposed
- **Date**: 2026-10-16

## Context

Two open issues need the server to tell a person something without the person looking at the
console: #863 item 3 (a host went `degraded` or `silent`, and nothing notifies anyone) and #61
(scheduled hunts "notify on new matches"; `server/hunt/README.md` lists it under "Not built yet":
"a run records `newMatchCount`; nothing is sent"). Both say the same thing: no notification
channel exists. `server/integrations/README.md` plans one
("signed outbound webhooks on case lifecycle events", paging with dedup by case) but nothing
is built.

What exists, read from the code on 2026-10-16:

- **Outbound requests: none.** The server makes no HTTP call to a customer-chosen URL, so there
  is no SSRF policy yet. A notification channel is the first one.
- **Silent agents already become cases** (`api/cron/detect-silent-agents`, one open case per
  agent, high severity). `degraded` (`lib/fleet-health.ts`) is computed on read and stamped
  (`lossObservedAt`); nothing records a *transition*, so "a host just became degraded" is not
  an event the server can name today.
- **Hunt runs** write a row per run with `newMatchCount` (`HuntRun`), from the cron or by hand.
- **Cron routes** (`CRON_SECRET`) are how the server does periodic work; there is no queue.
- **Roles:** `owner` and `admin` of a tenant can do admin actions (`requireTenantAdmin`, #803);
  every signed-in member can read. `AuditLog` records control-plane actions.
- **Secrets at rest:** decoy tokens are stored as SHA-256 only. A webhook secret has to be
  *used* (to sign), so it cannot be a hash.

## Decision

1. **One channel kind for now: a signed webhook.** A tenant admin registers an HTTPS URL and
   gets a signing secret (32 random bytes, hex, shown once). Slack, PagerDuty and e-mail are not
   built: a webhook receiver adapts to them, and each needs its own account, retries and
   templates. They are a later `kind`, not a reason to wait. (This also matches the
   `integrations` README.) A channel has an `events` list (which of the four events below it
   receives), a list of hunt ids for `hunt.new_matches` (see point 2), and its own cooldown.
2. **Events are named by what changed, not by what is true.** Version 1:
   `host.degraded`, `host.silent`, `host.recovered` (back to `healthy`), `hunt.new_matches`.
   - **Host events are transitions, found by the delivery cron.** `degraded` is derived on read
     and ends with a clock (the loss window), so no beacon marks its end. Each tick of the
     delivery cron compares, for every (channel, host) it serves, the host's `fleetStatus` with
     the last state **that channel** was told (`notification_state`, keyed by channel and
     subject; `fleetStatus` itself is not changed) and enqueues one row when they differ. The
     cost is up to one cron period of latency on a transition. `no_beacon` counts as `healthy`
     here. A host that stays degraded for a day sends one message and, on recovery, one more.
   - **The state is per channel, not per agent.** One channel in cooldown must not make another
     channel miss the transition, which a single `notified_status` on the agent would do. The
     state of a (channel, host) advances only when a row is enqueued for that channel.
   - **First evaluation records, it does not send.** The first time a channel evaluates a host
     its state is stored without a message, so registering a channel does not announce every
     host that is already degraded; its first message for that host is its next change.
   - **The cooldown defers by re-evaluation, nothing is queued meanwhile.** Within a channel's
     cooldown (point 4) no row is enqueued and the state is not advanced; the first tick after
     it re-evaluates and enqueues if the host still differs from what the channel was told. If
     the host went back to what the channel was told, nothing is sent (the receiver sees no
     `recovered` without a preceding `degraded`).
   - **`hunt.new_matches`** is queued by the hunt run after its row is written, when
     `newMatchCount` is above zero and the hunt is in a channel's hunt list (an admin decision on
     the channel, empty by default). A failure to queue is logged and never fails the run. The
     cooldown applies to it like to the others: a hunt with new matches on every run sends at
     most one message per channel and cooldown, not one per run (the console and the run history
     still show every run). A channel's hunt ids must belong to its tenant (checked when the
     channel is created or changed); a deleted hunt drops out of the lists that hold it.
3. **An outbox, not a call in the request path.** Producing an event writes a row
   (`notifications`: tenant, channel, event, subject, a dedup key, the payload, `seq`, attempts,
   `next_attempt_at`, `delivered_at`, `failed_at`, `locked_until`); a cron
   (`api/cron/deliver-notifications`, `CRON_SECRET`) sends the due rows. Ingest and hunt runs
   never wait on a customer's server, and a restart loses nothing.
   - **Lease.** The cron claims rows with `FOR UPDATE SKIP LOCKED` and sets `locked_until`, so two
     instances never send the same row concurrently. The lease (5 minutes) is longer than the
     cron's time budget for a tick (45 seconds, after which it stops claiming), so a slow tick
     cannot see its rows re-claimed. Delivery is **at least once** (a retry after a lost
     response): a receiver de-duplicates on the event `id`.
   - **Fairness.** A tick serves tenants round-robin, at most 10 rows per tenant, so one
     tenant's slow receivers do not delay the others.
   - **Order.** Each row carries a per-subject `seq`. A row waits behind an earlier *pending* row
     of the same subject (one still being retried). A row that has reached `failed` no longer
     blocks, otherwise a dead receiver would stall its subject for good. Receivers **must apply
     an event only if its `seq` is greater than the last one they applied for that subject** and
     discard the others; that rule, not the delivery order, is what keeps them from ending in an
     old state. For the same reason a `failed` row cannot be sent again from the console once a
     later row of the same subject exists: it is shown as superseded.
4. **The dedup key is `(channel, event, subject)` with a cooldown per channel.** `subject` is
   the agent id or the hunt id. The same key is not queued again while a pending row exists,
   nor within the channel's cooldown after a delivery (default 30 minutes, a setting of the
   channel, never below the cron's period), except `host.recovered`, which always goes. A
   flapping host therefore sends at most one `degraded` per channel and cooldown. A tenant may
   have at most 5 channels and 60 notifications a minute (counted on `last_attempt_at`); over
   that, rows wait (they are not dropped) and the console says the outbox is backed up (rows not
   attempted for over 5 minutes, also `backlog` on `GET /api/notify/channels`).
5. **Signed, minimal payloads.** `POST` with a JSON body (`id`, `event`, `tenant`,
   `occurred_at`, `seq`, `subject` with an id, a hostname and a link to the console page, and the
   few fields of the state change; `host.silent` also carries the link to the case the
   silent-agent cron opened **if it has opened one by then**, otherwise `case_url` is null) and
   `X-Synthaea-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">`.
   - **Every attempt is re-signed with a fresh `t`** (same event `id`, same body), so a retry
     hours later passes a freshness check; receivers should enforce a window of about 5 minutes.
   - **Rotation has an overlap.** For 24 hours after a rotation the header carries two
     signatures (`v1=<new>,v1=<old>`) and a receiver accepts either, so receivers do not break at
     the instant of rotation. The old secret is then deleted.
   - **No detection contents, no command lines, no case text**: a webhook is a pointer to the
     console, which has the authorization.
   - **Secrets and URLs at rest.** The signing secret and the URL are both stored with
     AES-256-GCM under a server key (`NOTIFY_SECRET_KEY`), the channel id as associated data,
     and a key id kept next to the ciphertext, so the key can be rotated without re-registering
     every channel. The URL is encrypted because its path is often a bearer credential (Slack
     and Teams style hooks); audit rows, logs and the console carry the host only. An unset key
     disables channel creation rather than storing anything in clear. A row whose secret cannot
     be opened (key gone, ciphertext not authentic) is a `blocked` failure and follows the retry
     schedule.
6. **The server is not a proxy into the network.** A channel URL must be `https` on port 443
   (or a port in an explicit server allowlist) and must not be followed through a redirect. A
   send has a **total deadline of 10 seconds** (resolve, connect, TLS and response, not an
   idle timeout) and a 64 KiB response cap whose body is never stored or shown.
   - **The send connects to the address that was validated.** The guard resolves the name once,
     checks every returned address, and the HTTP client connects to that IP, with the original
     `Host` and SNI, so a DNS rebinding between check and connect cannot pass. **TLS is verified
     against the original host name; there is no skip-verify.** The same check runs at
     registration and at each send.
   - **"Private" means:** loopback (`127/8`, `::1`), link-local (`169.254/16`, `fe80::/10`,
     including the cloud metadata address), RFC 1918, CGNAT `100.64/10`, `0.0.0.0/8`, multicast
     and reserved ranges, unique-local `fc00::/7` (which includes the IPv6 metadata address),
     and IPv4-mapped or IPv4-compatible IPv6 (`::ffff:127.0.0.1`), NAT64 (`64:ff9b::/96`) and 6to4
     (`2002::/16`) addresses, all judged by the IPv4 address they embed. Teredo (`2001::/32`) is
     refused outright. IP literals in the URL (decimal, octal and hex forms included) are parsed
     to an address and held to the same rule, or refused.
   - **No proxy.** The process's `HTTP(S)_PROXY` / `NO_PROXY` environment is ignored for this
     call; otherwise a proxy configured for the server would bypass the guard.
   - **No oracle for a tenant.** A test send returns a status code and a coarse error class:
     `blocked` (the name resolves to a refused address, or does not resolve, or the URL is
     refused: one class, so a tenant cannot tell the server's internal DNS from a miss),
     `connect`, `tls`, `timeout`, `http_status`. The finer cause goes to the server log only.
   - **A private receiver** (an on-prem SOAR) is allowed only through an explicit server setting,
     `NOTIFY_ALLOWED_PRIVATE_HOSTS`, set by whoever runs the server, never by a tenant. **Each
     entry names the tenants that may use it** (`<tenant id>:<host>`): on a multi-tenant server a
     tenant admin cannot point a channel at another tenant's on-prem host. There is no wildcard
     tenant.
7. **Delivery outcomes, retries and failure.**
   - **Delivered** is a `2xx` answer. `3xx` is a failure (no redirect is followed).
   - **Retried** with backoff (1, 5, 30 minutes, 2 and 6 hours: about 8 h 36 min in all) and
     then marked `failed`: network errors, timeouts, `5xx`, `408`, `425`, `429`. A `Retry-After`
     on `429` or `503` is honoured, capped at the largest step. A `410` pauses the channel at
     once (the receiver says it is gone). Any other `4xx` is `failed` without retry: the receiver
     says the request is wrong, and sending it again will not change that.
   - Five consecutive `failed` rows **pause** the channel and say so on its console page. A
     paused channel keeps queuing; its rows are kept and replayed, oldest first and per subject
     in order, when an admin re-enables it. A row of a paused or disabled channel is not claimed.
   - The last status code and a short error are kept, never the response body.
   - **Retention.** Delivered rows are deleted after 30 days and `failed` rows after 90, by the
     delivery cron.
8. **Who may do what.** Registering, rotating, disabling or deleting a channel needs a tenant
   `owner` or `admin`, and each is an `AuditLog` row (`notify.channel.create`, and so on);
   any signed-in member can see that channels exist, their state, the last result, failed rows
   and whether the outbox is backed up, never the secret or the URL beyond its host. A test
   send, a re-send of a failed row and a re-enable are admin actions. The console page is
   `/console/notifications`, linked from the console navigation.
9. **Out of scope:** per-user preferences and routing rules by severity or label; e-mail, Slack
   and PagerDuty `kind`s; inbound actions (acknowledge from the receiver); notifying on every new
   detection or case (the console and the cases already carry those: this is for the platform's
   own state, and for hunts a channel subscribes to); a console action on rollout (#863 item 4).

## Consequences

- #863 item 3 and #61's notification box get one mechanism. It is built in slices:
  (1) the channel model, the signing, the SSRF guard and the outbox with delivery, with a test
  send; (2) `host.*` transitions, evaluated by the delivery cron against per-channel state;
  (3) `hunt.new_matches`; (4) the console page for channels.
- `degraded` stays derived on read and `fleetStatus` is not changed; what the server stores is
  only what each channel was last told. The silent-agent cron is not changed either: `host.silent`
  comes from the same comparison.
- Host notifications cost up to one cron period of latency, and evaluation is skipped for a
  tenant with no channel subscribed to a host event, so nothing is recorded for it.
- A receiver that is down past the retry window (about 8 h 36 min) has rows `failed`, and its
  channel paused after five of them; the rows are kept and replayed in order when an admin
  re-enables it, and `seq` lets the receiver discard what a later event superseded. A
  `host.recovered` is never suppressed by the cooldown, because it is the only reliable way to
  close the loop.
- The first outbound call in the server is a new attack surface; point 6 is the part that needs
  the closest review, and the guard gets tests that resolve names to private addresses, to
  mapped, NAT64 and 6to4 addresses, to a Teredo address and to IP literals in every form.
- `server/integrations/README.md` stops promising paging in general: the webhook is built, the
  rest stay listed.

## Implementation status

- **Slice 1 (channel model, signing, SSRF guard, outbox with delivery, test send): built** in #863's first PR (`server/lib/notify/`, `server/app/api/notify/channels/`, `server/app/api/cron/deliver-notifications/`). Not built: the `host.*` producers (slice 2), `hunt.new_matches` (slice 3), the console page (slice 4); until slice 2 and 3 land no event is produced, so a channel only receives the test send.
- Detail the ADR left open: the "backed up" state is exposed as `backlog` (undelivered, not failed rows) on `GET /api/notify/channels`; the tenant limit of 60 a minute is counted on `last_attempt_at`; a row of a paused or disabled channel is not claimed; a row whose secret cannot be opened (key gone, ciphertext not authentic) is a `blocked` failure and follows the retry schedule.

## Resolved in review

- **Cooldown:** 30 minutes by default, per channel; never below the cron's period.
- **`host.silent`:** kept, with the link to the case in its payload when one exists (point 5).
- **Hunt subscription:** on the channel, not on the hunt. ADR-0025 point 8 lets every member edit
  hunts; a flag on the hunt would let a member aim notifications at admin-registered channels.
  With the subscription on the channel, it stays an admin decision.
- **Encryption key:** an environment variable for now, with the key id of point 5 so it can
  rotate; a KMS is the ADR-0027 conversation.
- **State per channel, not per agent; `seq` normative; allowlist scoped by tenant; URL
  encrypted; retention, outcomes and rotation overlap stated** (second review).
