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
   recovers, one more. A `hunt.new_matches` fires when a run's `newMatchCount` is above zero and
   its hunt opted in (a `notify` flag on the hunt, off by default), at most once per run.
3. **An outbox, not a call in the request path.** Producing an event writes a row
   (`notifications`: tenant, channel, event, a dedup key, the payload, attempts, `next_attempt_at`,
   `delivered_at`); a cron (`api/cron/deliver-notifications`, `CRON_SECRET`) sends the due rows.
   Beacon ingest and hunt runs never wait on a customer's server, and a restart loses nothing.
   Delivery is **at least once**: a receiver must de-duplicate on the event `id`.
4. **The dedup key is `(channel, event, subject)` with a cooldown.** `subject` is the agent id or
   the hunt id. The same key is not queued again while an undelivered row exists, nor within a
   cooldown after a delivery (default 30 minutes, per tenant setting), except `host.recovered`,
   which always goes. A flapping host therefore sends at most one `degraded` per cooldown and is
   summarised, not repeated. A tenant may have at most 5 channels and 60 notifications a minute;
   over that, rows wait (they are not dropped) and the console says the outbox is backed up.
5. **Signed, minimal payloads.** `POST` with a JSON body (`id`, `event`, `tenant`, `occurred_at`,
   `subject` with an id, a hostname and a link to the console page, and the few fields of the
   state change) and `X-Synthaea-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">`, so a
   receiver can check the secret and reject a replay. **No detection contents, no command lines,
   no case text**: a webhook is a pointer to the console, which has the authorization. The
   secret is stored encrypted with a server key (`NOTIFY_SECRET_KEY`); an unset key disables
   channel creation rather than storing the secret in clear.
6. **The server is not a proxy into the network.** A channel URL must be `https`, must not
   resolve (at registration and again at each send) to a loopback, link-local, private or
   metadata address, must not be followed through a redirect, and is called with a 5 s
   timeout and a 64 KiB response cap whose body is never stored or shown. A private receiver
   (an on-prem SOAR) is allowed only through an explicit server setting
   (`NOTIFY_ALLOWED_PRIVATE_HOSTS`), set by whoever runs the server, never by a tenant.
7. **Failure is visible and bounded.** A send is retried with backoff (1, 5, 30 minutes, 2 and
   6 hours) and then marked `failed`; five consecutive failed rows disable the channel and say so
   on its console page. The last status code and a short error are kept (never the response
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
- A receiver that is down for a day gets its backlog, oldest first, once it returns; a
  `host.recovered` that arrives after a `host.degraded` is the only reliable way to close the
  loop, so it is never suppressed by the cooldown.
- The first outbound call in the server is a new attack surface; point 6 is the part that needs
  the closest review, and the guard gets tests that resolve names to private addresses.
- `server/integrations/README.md` stops promising paging in general: the webhook is built, the
  rest stay listed.

## Open questions for review

- Is 30 minutes the right default cooldown, and should a tenant be allowed to set it lower than
  the cron's own period?
- Should `host.silent` notify at all, given that the silent-agent cron already opens a case?
  (It is here because a person who is not looking at the case list is the person #863 is about.)
- A hunt's `notify` flag: on the hunt, or a channel subscription to a list of hunts?
- Where the encryption key lives for a self-hosted install (an environment variable here; a KMS
  is the ADR-0027 conversation, not this one).
