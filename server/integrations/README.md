# server/integrations — SOAR, Ticketing, Paging

Where cases meet the organization's workflow (distinct from `export/`, which streams
telemetry to SIEMs — this is bidirectional case workflow):

- **Ticketing**: cases open/update Jira / ServiceNow issues with two-way status sync
  (close the ticket → annotate the case, resolve the case → resolve the ticket)
- **Operator notifications (built, ADR-0036, #863)**: a tenant admin registers a signed HTTPS
  webhook (`/api/notify/channels`, console page `/console/notifications`); `host.degraded`,
  `host.silent`, `host.recovered` and `hunt.new_matches` go through an outbox and a delivery cron
  (`/api/cron/deliver-notifications`, every minute), at least once. A message is a pointer to the
  console: no detection contents. What a receiver must do:
  - check `X-Synthaea-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">` with the channel
    secret and enforce a window of about 5 minutes on `t` (every attempt is signed again with a
    fresh `t`); for 24 hours after a secret rotation the header carries two values,
    `v1=<new>,v1=<old>`: accept either;
  - de-duplicate on the event `id`, and apply an event only if its `seq` is greater than the last
    one applied for that `subject`: delivery is at least once and a `failed` row no longer blocks
    the later ones, so `seq` is what keeps a receiver from ending in an old state;
  - answer `2xx` quickly (10 s in all). `408`, `425`, `429`, `5xx` and network errors are retried
    (1, 5, 30 minutes, 2 and 6 hours; a `Retry-After` on `429`/`503` is honoured); a `410` pauses
    the channel; any other answer is final. Five failed rows in a row pause the channel; its
    messages are kept and sent, oldest first, when an admin re-enables it. Delivered rows are
    kept 30 days, failed ones 90.
- **Paging** (not built): severity-threshold routing to PagerDuty/Opsgenie/Slack with dedup by
  case (a case pages once, not per detection)
- **SOAR/webhooks**: signed outbound webhooks on case lifecycle events, and a small
  inbound action API (acknowledge, annotate, trigger an EXISTING policy-gated
  playbook) — integrations get no capability the console does not have, and every
  inbound action is authenticated and audited like an analyst's.
