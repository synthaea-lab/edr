# ADR-0030: Decoy credentials and the fleet alarm

- **Status**: proposed
- **Date**: 2026-10-07

## Context

Issue #81's second done-when box: a decoy token planted on one host and used against the
control plane raises an alarm that names the host it came from. Canary files (ADR-0029) catch
someone reading a file on the host; a decoy credential catches what they do next, including
from another machine. It needs an agent half (plant a token, tell the server which one) and a
server half (recognise it when presented).

## Decision

1. **The server stores hashes, never tokens.** An agent registers the SHA-256 of each decoy
   token (`POST /api/ingest/decoy`, nginx proxy secret and mTLS like the other ingest routes).
   The control plane can recognise a decoy and cannot issue one or leak one.
2. **Registration is append-only, idempotent and bounded.** At most 256 hashes per agent
   (409 beyond), a hash belongs to the first agent that registered it (another agent's claim
   is counted as a conflict, not a transfer), and removing the decoys on the host does not
   delete the row: an attacker may hold an old copy of the file.
3. **A decoy is a `syn_dk_`-prefixed bearer token.** Only a presented bearer with that prefix
   and at most 256 characters is hashed and looked up, so ordinary rejected requests cost
   nothing.
4. **Where it is checked: the bearer-token guard, `verifyCronRequest`** (the `/api/cron/*`
   routes, `CRON_SECRET`). It is the only place the server evaluates a bearer token; session
   routes redirect to login before any token is read, and agent routes use mTLS. A decoy
   shaped like a cron secret (an env file next to the agent's config) is therefore the lure
   that fits. A request that presents it, whether the secret is configured or not, still gets
   the same 401 or 500 as any bad bearer.
5. **The alarm is a `Detection` row**, technique `T1552.001`, severity `high`, against the
   agent that planted the token, with the planting host's name, the route, the client address
   and user agent (each truncated to 200 characters). No schema change on the agent's wire
   format: the server writes its own detection, which the existing sweep groups into a case.
   One alarm per decoy per minute, so a client retrying a rejected token is one event:
   presentations that arrive together are coalesced in the process (a decoy being recorded is
   skipped by the others), and the database check bounds the rest. Behind several server
   processes two simultaneous presentations can still both pass, so the guarantee is "about
   one", not "exactly one".
6. **Best effort, silent, and after the answer.** The lookup never throws and never alters the
   response, and it runs **after** the 401 or 500 is ready: a decoy costs three queries and
   any other bad bearer none, so awaiting them would let a client tell a decoy from a wrong
   guess by response time. The report is started, not awaited. That assumes a long-running
   Node server (`next start`, the Docker image); a platform that freezes the process once the
   response is sent may cut it off, and would need Next's `after()` (Next 15) instead.
   `flushDecoyReports()` lets tests and a shutdown hook wait for the pending ones.
7. **The source address is what nginx saw.** `X-Real-IP` (set by nginx from the connection,
   replacing any client value) first; otherwise the **last** `X-Forwarded-For` hop, which is
   the address nginx appended, never the first, which is whatever the client wrote. Behind
   any other proxy neither is evidence. `nginx.conf` sets `X-Real-IP` for this.
8. **The `syn_dk_` prefix is a label, accepted.** It makes the cheap rejection possible (only
   a prefixed bearer is hashed and looked up), and it tells whoever reads the file that the
   token is a Synthaea decoy. The canary file already says so in its first line
   (`# SYNTHAEA DECOY ...`), so the prefix gives away nothing the header does not. Looking up
   every bearer by length and charset would hide it at the price of a query for every wrong
   guess; not worth it while the file is labelled anyway.
9. **The table comes from the schema, like every other model.** `server/.gitignore` lists
   `prisma/migrations/`, no migration is tracked, and the schema is applied with
   `prisma db push`; a new model therefore ships as a change to `schema.prisma` only. I
   checked the DDL anyway: `prisma migrate diff` from the previous schema gives the
   `CREATE TABLE "decoy_tokens"`, two indexes and two cascading foreign keys, and applying it
   to a database built from the previous schema leaves no drift. `docker-compose.yml` runs
   `prisma migrate deploy`, which with no tracked migration creates nothing in a clean
   checkout: that stack needs `db push` for this table as for all the others. Without the
   table a registration answers 500 and the alarm fails silently (it logs and moves on),
   which is the worst failure for this feature, so a deployment should check that
   registrations arrive (the `decoy_tokens` table fills; the agent logs the outcome).
10. **Unauthenticated lookups are rate limited at the proxy**: `/api/cron/` gets 10 requests
   per second per address, burst 20, in `nginx.conf` (429 beyond), since a flood of
   `syn_dk_`-prefixed bearers is otherwise one indexed query each.
11. **The agent plants one token in each credentials canary and each config canary**
   (`api-token : syn_dk_<32 hex>`, `cron_secret = syn_dk_<32 hex>`), derived from the install's
   seed and the canary's index: different per install and per canary, stable across restarts,
   and absent from finance and notes canaries. At start it registers the SHA-256 of the planted
   tokens (lowercase hex of the UTF-8 bytes, the same constant asserted on both sides) in a
   detached thread, retrying over about half a day (5 s, 15 s, 1 min, 5 min, 15 min, 30 min,
   then hourly, 12 tries) and stopping at once only on a refusal that will not change: a 400,
   409, 413 or 422, or an error that cannot be fixed by asking again (serialization,
   configuration). A 401, 403, 404, 408, 429 or any 5xx, a TLS or I/O error and every
   network error are retried, because the thread runs once per start and a daemon may not
   restart for days. The tokens registered are the ones **found in the canary files on
   disk** after planting, read back, never the plan's: a canary planted by an earlier build
   keeps its old content and holds no decoy, and a skipped or foreign file holds none of
   ours.
   The next start tries again. Standalone, or with the upload disabled, the tokens are planted
   and nothing recognises them.
## Consequences

- The alarm fires for a decoy used against a cron route. A decoy presented anywhere else
  (a session route, a third-party service) is not seen: widening it needs the server to read
  bearer tokens on more routes, which is a separate decision.
- Registration happens once per start. If the control plane loses its table, decoys are
  recognised again only after the agent restarts.
- A token the operator removes by deleting its canary is still recognised: rows are never
  deleted.
- Stored `event` and `meta` carry attacker-supplied header text: bounded and never rendered
  as markup, but console views that show `meta` must treat it as untrusted.
