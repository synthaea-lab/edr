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
   (409 beyond), and removing the decoys on the host does not delete the row: an attacker may
   hold an old copy of the file. The same holds for the agent row: `decoy_tokens.agent_id` is
   `NoAction`, so deleting an agent that holds decoy hashes fails instead of disarming them
   (deleting the tenant removes both). A registration takes a per-agent advisory lock for its
   transaction, so the cap is not a count-then-insert two requests can both pass.
   **A hash is held per agent, not first-come-first-served.** The row is unique on
   `(agent_id, token_sha256)`, and the same hash may be held by several agents, in any tenant.
   The alarm looks a presented bearer up with no tenant (the cron routes are unauthenticated),
   so it cannot pick *the* owner; instead it raises one alarm **per holder** (at most 32 per
   presentation). That removes the three problems of a global unique key together: an agent
   that has read another's token cannot take its hash (registering the same one just adds a
   second alarm, naming the squatter too, which is itself worth an analyst's look); there is no
   "already taken" answer, so the response carries only `registered` and a caller learns
   nothing about hashes it did not send; and two agents racing on one hash both succeed. The
   cost is that one presentation can produce several alarms, each naming its own agent and
   host, when a hash is held twice.
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
   `flushDecoyReports()` waits for the pending ones: `instrumentation.ts` calls it on SIGTERM
   and SIGINT (waiting at most 5 s), so an alarm written just before a stop is not lost.
   Next 14.2.35 registers its own SIGINT/SIGTERM handler (`server.close()` then
   `process.exit(0)`, in `start-server.js`) unless `NEXT_MANUAL_SIG_HANDLE` is set, and both
   handlers run, so Next's could exit before the flush wrote. The production image therefore
   sets `NEXT_MANUAL_SIG_HANDLE=true`, which makes the flush the only handler (it exits itself
   when done or after 5 s), and the server logs an error at start in production if the flag is
   missing. Not tested against a real `docker stop` with a blocked lookup.
7. **The source address is what nginx saw.** `X-Real-IP` (set by nginx from the connection,
   replacing any client value) first; otherwise the **last** `X-Forwarded-For` hop, which is
   the address nginx appended, never the first, which is whatever the client wrote. Behind
   any other proxy neither is evidence. `nginx.conf` sets `X-Real-IP` for this. The address
   is recorded only when the request carries the proxy secret (`verifyProxyAuth`); a call
   straight to the app port records `unverified`, since it can write any header. The
   host name in the alarm is **self-declared** at enrollment (bounded to 253 printable
   characters there and in the title): the title leads with the agent id, which the server
   issued, and `meta.planting_agent_id` is the identifier to trust. An alarm is deduplicated per
   decoy **and source address** within the minute, so a second address is a second alarm.
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
   which is the worst failure for this feature: the server now says so at start (item 13),
   and a deployment should still check that registrations arrive (the `decoy_tokens` table
   fills; the agent logs the outcome).
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
12. **Unauthenticated lookups are bounded in the process too.** At most 16 decoy-shaped
    bearers are looked up at once; the overflow waits in a queue of at most 1024, and when
    that is full the *oldest* waiting one is shed and counted (the count said in the log at
    powers of two). A bearer that is not decoy-shaped costs nothing. Dropping on full slots
    would let 16 junk bearers sent alongside a stolen token shed the real alarm; queueing means
    the real one waits behind at most 1024 older lookups and is shed only after that many newer
    ones arrive. A flood that sustains more than the database drains can still shed a real
    alarm: that is the price of bounded memory, and the proxy limit (item 10) keeps one
    address from doing it alone.
13. **The server says at start if the table is missing.** `instrumentation.ts` checks that
    `decoy_tokens` exists and logs the fix (`prisma db push`) if not; it never fails the start
    (the database may not be reachable yet).

## Consequences

- **Accepted, from the review of #732.** A hash is never removed, so an agent whose decoys
  rotate reaches the 256 cap and gets 409 from then on: removal would disarm a token an
  attacker may still hold (item 2), and the cap bounds rows; an operator who rotates needs a
  cleaner that keeps the hashes, which is a separate decision. The alarm lookup has no tenant
  filter (item 2), so an enrolled agent of another tenant that learns a hash can register it
  and be alarmed too: the cost is an extra alarm in its own tenant naming itself, and it needs
  a leaked hash, which the design treats as non-secret. The cooldown is per process (below).
- **Known gap, not closed here.** The cooldown across several server processes is "about one": the in-flight set is per process, the database check bounds it and does not eliminate it. A process killed with SIGKILL (not SIGTERM) can still lose an alarm written just before.
- The alarm fires for a decoy used against a cron route. A decoy presented anywhere else
  (a session route, a third-party service) is not seen: widening it needs the server to read
  bearer tokens on more routes, which is a separate decision.
- Registration happens once per start. If the control plane loses its table, decoys are
  recognised again only after the agent restarts.
- A token the operator removes by deleting its canary is still recognised: rows are never
  deleted.
- Stored `event` and `meta` carry attacker-supplied header text: bounded and never rendered
  as markup, but console views that show `meta` must treat it as untrusted.
