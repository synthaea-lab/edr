# server/integrations — SOAR, Ticketing, Paging

Where cases meet the organization's workflow (distinct from `export/`, which streams
telemetry to SIEMs — this is bidirectional case workflow):

- **Ticketing**: cases open/update Jira / ServiceNow issues with two-way status sync
  (close the ticket → annotate the case, resolve the case → resolve the ticket)
- **Operator notifications (built, ADR-0036, #863)**: a tenant admin registers a signed HTTPS
  webhook (`/api/notify/channels`); events go through an outbox and a delivery cron
  (`/api/cron/deliver-notifications`), at least once, signed `X-Synthaea-Signature`
  (`t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">`, re-signed on every attempt: enforce a
  ~5 minute window on `t` and de-duplicate on the event `id`). Built so far: the channel model,
  signing, the SSRF guard, the outbox and delivery, and the admin routes with a test send.
  The `host.*` and `hunt.new_matches` producers and the console page are the next slices.
- **Paging** (not built): severity-threshold routing to PagerDuty/Opsgenie/Slack with dedup by
  case (a case pages once, not per detection)
- **SOAR/webhooks**: signed outbound webhooks on case lifecycle events, and a small
  inbound action API (acknowledge, annotate, trigger an EXISTING policy-gated
  playbook) — integrations get no capability the console does not have, and every
  inbound action is authenticated and audited like an analyst's.
