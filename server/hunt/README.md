# server/hunt — Threat Hunting

Analyst-driven hunting over fleet telemetry: ad-hoc queries across the event and
detection stores, saved hunts, and scheduled hunts that page an analyst on new matches.

## Built (issue #61, slice 1; ADR-0025, proposed)

- **Saved hunts** (`Hunt`, `HuntRun` in `prisma/schema.prisma`): a structured, versioned
  `HuntQuery` over the tenant's detections, an owner, an optional schedule, and a result
  history. Code: `lib/hunt.ts` (validate, compile, run), `lib/hunt-input.ts` (request bodies).
- **API** (session, tenant-scoped): `GET/POST /api/hunts`, `GET/PATCH/DELETE /api/hunts/[id]`,
  `POST /api/hunts/[id]/run`.
- **Scheduler**: `GET /api/cron/run-hunts` (CRON_SECRET) runs the due scheduled hunts and
  prunes history.
- **Graduation** (#618): `POST /api/hunts/[id]/graduate` (`lib/hunt-graduation.ts`) answers a
  draft Sigma rule and its samples file from the hunt's newest finished run, for a person to
  review and open as a PR; see `docs/detection/detection-as-code.md`. It writes nothing.
- **Console** (`/console/hunts`): the list, a hunt's run history with Run now, and a create
  and edit form (`/console/hunts/new`, `/console/hunts/[id]/edit`). The form turns its fields
  into the API body with `lib/hunt-form.ts`, which runs the same validation as the API. The
  list reads each hunt's newest run and its newest run with a result in one query
  (`lib/hunt-runs.ts`, two lateral index lookups per hunt); numbers from an older run than the
  newest say which run they come from. The edit page warns when the stored query no longer
  parses, because saving replaces it with the form's. A "Running" run turns "Did not finish"
  after three transaction timeouts plus a margin (`RUNNING_GRACE_MS`). Both client buttons treat
  a redirect to the sign-in page as an expired session, not as success.
- The query is **not SQL**: `lastHours`, `techniques`, `severities`, `agentIds`, `text`.

## Not built yet

- Deleting a hunt from the console (the API has `DELETE`).
- Notification on new matches (a run records `newMatchCount`; nothing is sent).
- The raw event archive as a second source (needs `server/datalake`, #77).
- Graduation beyond the assisted Sigma draft: a console button, the PR opened from the server, a YARA or IOC-set draft, a selection built from the raw archive.
- Live endpoint queries (ask one host "what is running right now?") ride the
  `response::live` channel with its policy gates, not a separate mechanism.
