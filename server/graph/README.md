# server/graph — Entity Graph

The fleet-wide graph of entities and their relations: hosts, processes, files (by
hash or path), network endpoints/domains, and identities, with the edges between
them (`spawned`, `opened`, `connected_to`, `resolved`, `logged_in`, `ran_on`).

One graph, four consumers:
- **Cases** — a case is a subgraph plus evidence; the console renders it as such
- **Fleet correlation** (`server/fleet`) — blast-radius = graph neighborhood
- **Hunting** (`server/hunt`) — pivots ("everywhere this hash ran", "everything this
  identity touched") are graph traversals
- **Prevalence** (`server/prevalence`) — node degree/frequency is the raw material

## Where it actually lives

The implementation is `lib/graph.ts`, not a directory of its own: two pure
functions (`caseSubgraph`, `hashPivot`) and the extraction/merge helpers they are
built from, called by two API routes —
[`GET /api/cases/[id]/graph`](../app/api/cases/%5Bid%5D/graph/route.ts) and
[`GET /api/graph/pivot`](../app/api/graph/pivot/route.ts).

**Nothing is persisted as a graph.** Both functions are computed fresh from rows
already read for another reason:

- `caseSubgraph` folds a case's `Detection.event` rows (`lib/graph.ts`'s
  `extractGraphFacts`, one event type at a time — `exec`, `file_open`, `connect`,
  `dns_query`, `session` today) into deduplicated nodes and edges.
- `hashPivot` turns the `PrevalenceSighting` rows for one `(kind, key)` into a
  subject node and one host node per agent that showed it. Its `kind` is
  `PivotKind` (`sha256`/`image_path`/`domain`), not the full `PrevalenceKind` —
  `transition` pairs two entities (`"parent -> child"`), not one, so there is
  no single node it could become; `GET /api/graph/pivot` rejects it with 400
  before `hashPivot` is ever reached. A `sha256`/`image_path` subject is keyed
  exactly as `extractGraphFacts` keys the same file (`sha256:<hash>` /
  `path:<normalized path>`) so a pivot's node and a case subgraph's node for
  the same file are the same node, joinable by a console that overlays both.
  The sightings list itself is capped at `MAX_PIVOT_HOSTS`; the pivot route's
  response carries `truncated: true` when a key's real host count exceeded it,
  rather than silently handing back a partial list a console would read as
  the whole fleet.

**Why no raw-telemetry projection yet:** `server/datalake` (issue #77), the full
event stream's actual store, does not exist. `POST /api/ingest/events` already
says this plainly — an accepted event is counted into prevalence and then
dropped. So this graph is scoped to the two sources that are actually durable: a
case's own detections (rich, but only what fired a rule) and prevalence (every
execution, but pre-aggregated to per-host counts, not full events). Widening
`extractGraphFacts` to more event types, or building a materialized store the
datalake can rebuild on a schedule, are both natural next slices once #77 lands —
not blocked on it for what exists today.

**Kept honest, by construction, not by convention:** a store that is never
written cannot drift from the events it is a projection of. `tests/unit/graph.test.ts`
still proves the "rebuild from events" property the issue's acceptance criteria
ask for — computing the same facts twice, or in a different order, is identical
— because there is nothing to drop and replay in the first place.
