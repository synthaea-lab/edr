# ADR-0025: Saved hunts: a structured, versioned query over the detection store

- **Status**: proposed
- **Date**: 2026-10-06

## Context

Issue #61 asks for analyst hunting: ad-hoc queries, saved hunts with an owner, a schedule
and a result history, and a path from a hunt that keeps matching to detection content.
That last step is #618 (detection-as-code gap 4), and it has nothing to export while no
saved hunt exists. Three things in #61 cross a boundary and need a decision before code:

- What a hunt's query *is*. Raw SQL over the detection tables is the most flexible and the
  most dangerous: it can name any table, ignore the tenant, and run for as long as it likes.
- What it searches. The issue names the detection and case store and the raw event archive;
  the archive (`server/datalake`, #77) does not exist yet.
- What "new matches" means, since a scheduled hunt is meant to notify on them and nothing
  notifies yet.

## Decision

1. **A hunt's query is a structured `HuntQuery` (JSON, `version: 1`), never SQL.**
   Fields: `lastHours` (a relative window, so a scheduled hunt keeps meaning "recently"),
   `techniques` (an ATT&CK id also matches its sub-techniques), `severities`, `agentIds`,
   and `text` (a literal, case-insensitive substring of the detection's stored event JSON).
   It is validated on every write, refuses unknown fields, and is compiled to parameterized
   SQL that is always scoped to the caller's tenant and window. A hunt cannot name a table
   or a column, and a value is bound as a parameter, never interpolated.
2. **Slice 1 searches the detection store only.** The raw event archive is a later query
   `version`; a hunt records the version it was written for.
3. **A hunt is versioned.** `Hunt.version` goes up when `query` changes; every `HuntRun` keeps
   the version and a copy of the query it ran, so editing a hunt never rewrites its history.
4. **Runs are bounded.** Each runs in a transaction with a 10 s statement timeout; a run that
   fails (a timeout, or a stored query that no longer parses) is recorded on the run with its
   `error`, not thrown, so one bad hunt does not stop the scheduler's batch. A run keeps its
   counts and the newest 100 matching detection ids; the newest 100 runs per hunt are kept.
5. **"New match" means ingested since the hunt's previous successful run started**
   (`detection.created_at`), not "first seen on the fleet". It is a count on the run. Nothing
   is notified yet; a notification channel is a separate decision.
6. **Scheduling is a cron route**, `GET /api/cron/run-hunts` (CRON_SECRET), called every few
   minutes: a hunt runs when its last run is older than its `scheduleMinutes` (5 minutes to a
   week). At most 50 hunts per call; a tenant may have 200 hunts.

## Consequences

- #618 has something to build on: a saved hunt with a query, an owner, a schedule and a result
  history. Whether a hunt "keeps matching" is read from its runs. The open question #618 left
  (the matching and negative samples are Rust test data keyed by rule title) is untouched.
- The query is deliberately less expressive than SQL. Anything an analyst needs that it cannot
  say (a join, a field-level predicate on the event JSON) is a new field in a new query
  version, reviewed like any other change, rather than an escape hatch.
- `text` is a substring scan of the event JSON inside the tenant and window: indexed by
  `(tenant_id, timestamp)` only, so a wide window with a rare string is the expensive case.
  The statement timeout is the bound, not an optimisation.
- Not built in this slice: the console UI, notifications, graduation itself (#618), live
  "ask this host now" queries (they ride the `response::live` channel and its gates), and the
  event archive.
