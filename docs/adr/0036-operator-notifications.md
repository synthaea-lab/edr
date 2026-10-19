# ADR-0036: Operator notifications: signed webhooks from an outbox, on state changes

- **Status**: proposed
- **Date**: 2026-10-16

## Context

Two open issues need the server to tell a person something without the person looking at the
console: #863 item 3 (a host went `degraded` or `silent`, and nothing notifies anyone) and #61
(a saved hunt has new matches; "a run records `newMatchCount`, nothing is sent"). Both say the
same thing: no notification channel exists. `server/integrations/README.md` plans one
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
   gets a signing secret (shown once). Slack, PagerDuty and e-mail are not built: a webhook
   receiver adapts to them, and each needs its own account, retries and templates. They are a
   later `kind`, not a reason to wait. (This also matches the `integrations` README.)
2. **Events are named by what changed, not by what is true.** Version 1:
   `host.degraded`, `host.silent`, `host.recovered` (back to `healthy`), `hunt.new_matches`.
   A notification fires on a **transition** (healthy to degraded), not on every beacon in which
   the host is still degraded. The server records the last notified state per agent
   (`notified_status`), so a host that stays degraded for a day sends one message and, when it
   recovers, one more. `notified_status` advances only when a row is enqueued, so a message
   deferred by the cooldown (point 4) is not lost: the delivery cron sends it when the cooldown
   ends if the host is still in that state, and drops it if the host has recovered meanwhile (a
   receiver may therefore see a `host.recovered` with no preceding `host.degraded`, and must
   accept it). A `hunt.new_matches` fires when a run's `newMatchCount` is above zero and
   a channel subscribes to its hunt (an admin decision on the channel, none by default), at most
   once per run.
3. **An outbox, not a call in the request path.** Producing an event writes a row
   (`notifications`: tenant, channel, event, a dedup key, the payload, attempts, `next_attempt_at`,
   `delivered_at`); a cron (`api/cron/deliver-notifications`, `CRON_SECRET`) sends the due rows.
   Beacon ingest and hunt runs never wait on a customer's server, and a restart loses nothing.
   The cron claims due rows under a lease (`FOR UPDATE SKIP LOCKED`, a `locked_until` column), so
   two server instances never send the same row concurrently. Delivery is **at least once**
   (a retry after a lost response, not routine double sends): a receiver must de-duplicate on the
   event `id`. Rows of the same subject are delivered in order: a row waits behind an earlier
   undelivered row of the same subject, so `host.recovered` never overtakes a `host.degraded`
   that is still backing off. Each row also carries a per-subject `seq` for receivers that want
   to check.
4. **The dedup key is `(channel, event, subject)` with a cooldown.** `subject` is the agent id or
   the hunt id. The same key is not queued again while an undelivered row exists, nor within a
   cooldown after a delivery (default 30 minutes, per tenant setting, never below the cron's period), except `host.recovered`,
   which always goes. A flapping host therefore sends at most one `degraded` per cooldown and is
   summarised, not repeated. A tenant may have at most 5 channels and 60 notifications a minute;
   over that, rows wait (they are not dropped) and the console says the outbox is backed up.
5. **Signed, minimal payloads.** `POST` with a JSON body (`id`, `event`, `tenant`, `occurred_at`, `seq`,
   `subject` with an id, a hostname and a link to the console page, and the few fields of the
   state change; `host.silent` also carries the link to the case the silent-agent cron already
   opened, so the receiver sees it is the same incident) and `X-Synthaea-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">`, so a
   receiver can check the secret and reject a replay. **Every attempt is re-signed with a fresh
   `t`** (same event `id`, same body otherwise), so a retry hours later passes a freshness
   check; receivers should enforce a window of about 5 minutes on `t`. **No detection contents, no command lines,
   no case text**: a webhook is a pointer to the console, which has the authorization. The
   secret is stored with AES-256-GCM under a server key (`NOTIFY_SECRET_KEY`), the channel id as
   associated data, and a key id kept next to the ciphertext, so the key can be rotated
   without re-registering every channel. An unset key disables channel creation rather than
   storing the secret in clear.
6. **The server is not a proxy into the network.** A channel URL must be `https` on port 443
   (or a port in an explicit server allowlist), must not be followed through a redirect, and is
   called with a 5 s timeout and a 64 KiB response cap whose body is never stored or shown.
   - **The send connects to the address that was validated.** The guard resolves the name once,
     checks every returned address, and the HTTP client connects to that IP (original `Host`
     and SNI kept), so a DNS rebinding between check and connect cannot pass. The same check runs
     at registration and again at each send.
   - **"Private" means:** loopback (`127/8`, `::1`), link-local (`169.254/16`, `fe80::/10`,
     including the cloud metadata address), RFC 1918, CGNAT `100.64/10`, `0.0.0.0/8`, multicast
     and reserved ranges, unique-local `fc00::/7` (which includes the IPv6 metadata address),
     and IPv4-mapped or IPv4-compatible IPv6 (`::ffff:127.0.0.1`) judged by the embedded IPv4.
     IP literals in the URL (decimal, octal and hex forms included) are parsed to an address and
     held to the same rule, or refused.
   - **No proxy.** The process's `HTTP(S)_PROXY` / `NO_PROXY` environment is ignored for this
     call; otherwise a proxy configured for the server would bypass the guard.
   - A test send returns a status code and a coarse error class (`blocked`, `dns`, `connect`,
     `tls`, `timeout`, `http_status`), never the finer cause, so it is not a port-scan oracle.
   - A private receiver (an on-prem SOAR) is allowed only through an explicit server setting
     (`NOTIFY_ALLOWED_PRIVATE_HOSTS`), set by whoever runs the server, never by a tenant.
7. **Failure is visible and bounded.** A send is retried with backoff (1, 5, 30 minutes, 2 and
   6 hours) and then marked `failed`; five consecutive failed rows **pause** the channel and say so on its
   console page. A paused channel keeps queuing: its rows are kept (not dropped) and replayed,
   oldest first, when an admin re-enables it. Rows already marked `failed` stay visible and
   can be re-sent from the console. The last status code and a short error are kept (never the response
   body).
8. **Who may do what.** Registering, rotating, disabling or deleting a channel needs a tenant
   `owner` or `admin`, and each is an `AuditLog` row (`notify.channel.create`, and so on);
   any signed-in member can see that channels exist and whether they work, never the secret or
   the full URL path (shown as host only). A test send is an admin action.
9. **Out of scope:** per-user preferences and routing rules by severity or label; e-mail, Slack
   and PagerDuty `kind`s; inbound actions (acknowledge from the receiver); notifying on every new
   detection or case (the console and the cases already carry those: this is for the platform's
   own state, and for hunts that opt in); a console action on rollout (#863 item 4).

## Consequences

- #863 item 3 and #61's notification box get one mechanism. It is built in slices:
  (1) the channel model, the signing, the SSRF guard and the outbox with delivery, with a test
  send; (2) `host.*` transitions (a column on `agent_health`, set where the beacon is stored,
  and the silent cron); (3) `hunt.new_matches`; (4) the console page for channels.
- Slice 2 changes what "degraded" costs: it becomes a recorded transition. It must not change
  how `fleetStatus` is computed (`degraded` stays derived on read; the stored `notified_status`
  is only what the server last told someone).
- A receiver that is down past the retry window (6 h) has its channel paused after five failed
  rows; the backlog is kept and replayed oldest first, per subject in order, when an admin
  re-enables it. A `host.recovered` that arrives after a `host.degraded` is the only reliable way to close the
  loop, so it is never suppressed by the cooldown.
- The first outbound call in the server is a new attack surface; point 6 is the part that needs
  the closest review, and the guard gets tests that resolve names to private addresses.
- `server/integrations/README.md` stops promising paging in general: the webhook is built, the
  rest stay listed.

## Resolved in review

- **Cooldown:** 30 minutes by default; a tenant may not set it below the cron's period.
- **`host.silent`:** kept, with the link to the case in its payload (point 5).
- **Hunt `notify`:** the subscription lives on the channel (a channel lists the hunts it
  receives), not on the hunt. ADR-0025 point 8 lets every member edit hunts; a flag on the hunt
  would let a member aim notifications at admin-registered channels. With the subscription on
  the channel, it stays an admin decision.
- **Encryption key:** an environment variable for now, with the key id of point 5 so it can
  rotate; a KMS is the ADR-0027 conversation.
