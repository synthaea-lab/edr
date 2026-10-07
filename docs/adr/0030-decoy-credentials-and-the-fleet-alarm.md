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
   agent that planted the token, with the planting host's name, the route, the forwarded
   client address and user agent (each truncated to 200 characters). No schema change on the
   agent's wire format: the server writes its own detection, which the existing sweep groups
   into a case. One alarm per decoy per minute, so a client retrying a rejected token is one
   event.
6. **Best effort and silent.** The lookup never throws and never alters the response.

## Consequences

- The alarm fires for a decoy used against a cron route. A decoy presented anywhere else
  (a session route, a third-party service) is not seen: widening it needs the server to read
  bearer tokens on more routes, which is a separate decision.
- The agent half (generating the token from the install's seed, planting it in a canary,
  registering the hashes) is a separate change; until it lands nothing registers a token.
- Stored `event` and `meta` carry attacker-supplied header text: bounded and never rendered
  as markup, but console views that show `meta` must treat it as untrusted.
