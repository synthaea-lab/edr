import type { PrevalenceKind } from "@/lib/prevalence";

/**
 * Fleet entity graph (issue #72): hosts, processes, files (by hash or path),
 * network endpoints/domains, and identities, with the edges between them.
 *
 * Scope, stated plainly: there is no raw-telemetry store yet (`server/datalake`,
 * issue #77) — an ingested event that triggers no rule is counted into fleet
 * prevalence (`lib/prevalence.ts`) and then dropped. So this graph is built from
 * the two durable sources that actually exist:
 * - `Detection.event`: a full normalized event, but only for what fired a rule —
 *   enough to render one case's subgraph (a case has few detections).
 * - `PrevalenceSighting`: every execution is counted here regardless of whether
 *   it fired a rule, per `(kind, key, agentId)` — not a full event, but exactly
 *   the host-breadth fact the "everywhere this hash ran" pivot needs.
 *
 * Nothing here is persisted as a graph. Both `caseSubgraph` and `hashPivot`
 * are pure folds over rows already read for another reason, computed fresh
 * every call — the strongest version of "rebuildable from events, never the
 * system of record" is a store that was never written in the first place.
 * Widening to the full event stream is `server/datalake` (#77) first.
 */

export type NodeKind = "host" | "process" | "file" | "network" | "identity";
export type EdgeKind = "spawned" | "opened" | "connected_to" | "resolved" | "logged_in" | "ran_on";

export type NodeRef = { kind: NodeKind; key: string };

export type GraphNode = NodeRef & {
  label: string;
  /** Free-form, kind-specific attributes a console can show on selection. */
  attrs: Record<string, string>;
  /** When this fact about the node was last observed — the merge tie-breaker
   * below, so two foldings of the same facts in a different order agree on
   * which of several labels for the same key is current, not whichever one
   * happened to be seen last in that particular order. */
  at: Date;
};

export type GraphEdge = {
  kind: EdgeKind;
  from: NodeRef;
  to: NodeRef;
  at: Date;
};

export type Graph = { nodes: GraphNode[]; edges: GraphEdge[] };

/** Stable identity for a node, independent of discovery order. */
export function nodeId(node: NodeRef): string {
  return `${node.kind}\u0000${node.key}`;
}

function edgeId(edge: Pick<GraphEdge, "kind" | "from" | "to">): string {
  return `${edge.kind}\u0000${nodeId(edge.from)}\u0000${nodeId(edge.to)}`;
}

/** Windows paths compare case-insensitively; mirrors `lib/prevalence.ts`. */
const WINDOWS_PATH = /^([a-z]:\\|\\\\)/i;
function normalizePath(path: string): string {
  return WINDOWS_PATH.test(path) ? path.toLowerCase() : path;
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** A process node's key: the execution instance, not the binary (#519's generation
 * stamp when the sensor has one, else the event's own timestamp as a cheap
 * stand-in — collisions need the same host, pid and tick, which a single case's
 * handful of detections will not produce in practice). Two runs of the same
 * binary are two process nodes, linked to the same `file` node. */
function processKey(hostKey: string, pid: unknown, generation: unknown, timestampNs: unknown): string | null {
  if (typeof pid !== "number") return null;
  const tick = typeof generation === "number" ? generation : typeof timestampNs === "number" ? timestampNs : 0;
  return `${hostKey}:${pid}:${tick}`;
}

function fileKey(sha256: unknown, path: unknown): NodeRef | null {
  const sha = nonEmptyString(sha256)?.toLowerCase();
  if (sha) return { kind: "file", key: `sha256:${sha}` };
  const p = nonEmptyString(path);
  return p ? { kind: "file", key: `path:${normalizePath(p)}` } : null;
}

/**
 * Graph facts implied by one event on one host. Pure and tolerant, same
 * discipline as `lib/prevalence.ts`'s `extractObservations`: an event of a
 * shape this does not recognize yields nothing, never an error — this runs
 * on an attacker-influenced `Detection.event` after the event is already
 * stored.
 */
export function extractGraphFacts(hostKey: string, event: unknown, at: Date): Graph {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  if (typeof event !== "object" || event === null) return { nodes, edges };
  const e = event as Record<string, unknown>;
  const meta = typeof e.meta === "object" && e.meta !== null ? (e.meta as Record<string, unknown>) : {};

  // Pushed only by a branch that actually ends up referencing it (an edge to
  // or from it): an event of a type this function does not recognize must
  // yield nothing at all, not a lone host node, same tolerance as every
  // other node/edge here.
  const host: NodeRef = { kind: "host", key: hostKey };
  const addHost = (): void => {
    nodes.push({ ...host, label: hostKey, attrs: {}, at });
  };

  const self = processKey(hostKey, meta.pid, meta.process_generation, meta.timestamp_ns);
  const comm = nonEmptyString(meta.comm);

  if (e.type === "exec") {
    const image = nonEmptyString(e.image_path);
    if (self && image) {
      const proc: NodeRef = { kind: "process", key: self };
      nodes.push({ ...proc, label: image, attrs: { comm: comm ?? "", image_path: image }, at });

      const file = fileKey(e.sha256, image);
      if (file) {
        addHost();
        nodes.push({ ...file, label: image, attrs: {}, at });
        edges.push({ kind: "ran_on", from: file, to: host, at });
        edges.push({ kind: "opened", from: proc, to: file, at });
      }

      const parentImage = nonEmptyString(e.parent_image_path);
      const parentComm = nonEmptyString(e.parent_comm);
      const parentGeneration = meta.parent_process_generation;
      const parentLabel = parentImage ?? parentComm;
      if (parentLabel && typeof meta.ppid === "number") {
        const parentSelf = processKey(hostKey, meta.ppid, parentGeneration, undefined);
        if (parentSelf) {
          const parent: NodeRef = { kind: "process", key: parentSelf };
          nodes.push({ ...parent, label: parentLabel, attrs: {}, at });
          edges.push({ kind: "spawned", from: parent, to: proc, at });
        }
      }
    }
  } else if (e.type === "file_open") {
    const path = nonEmptyString(e.path);
    if (self && path && comm) {
      const proc: NodeRef = { kind: "process", key: self };
      nodes.push({ ...proc, label: comm, attrs: { comm }, at });
      const file = fileKey(undefined, path);
      if (file) {
        nodes.push({ ...file, label: path, attrs: {}, at });
        edges.push({ kind: "opened", from: proc, to: file, at });
      }
    }
  } else if (e.type === "connect") {
    const daddr = nonEmptyString(e.daddr);
    const dport = e.dport;
    if (self && comm && daddr && (typeof dport === "number" || typeof dport === "string")) {
      const proc: NodeRef = { kind: "process", key: self };
      nodes.push({ ...proc, label: comm, attrs: { comm }, at });
      const net: NodeRef = { kind: "network", key: `tcp:${daddr}:${dport}` };
      nodes.push({ ...net, label: `${daddr}:${dport}`, attrs: {}, at });
      edges.push({ kind: "connected_to", from: proc, to: net, at });
    }
  } else if (e.type === "dns_query") {
    const query = nonEmptyString(e.query)?.toLowerCase().replace(/\.$/, "");
    if (self && comm && query) {
      const proc: NodeRef = { kind: "process", key: self };
      nodes.push({ ...proc, label: comm, attrs: { comm }, at });
      const domain: NodeRef = { kind: "network", key: `dns:${query}` };
      nodes.push({ ...domain, label: query, attrs: {}, at });
      edges.push({ kind: "resolved", from: proc, to: domain, at });
    }
  } else if (e.type === "session") {
    const user = nonEmptyString(e.target_user);
    if (user) {
      addHost();
      const identity: NodeRef = { kind: "identity", key: user };
      nodes.push({ ...identity, label: user, attrs: {}, at });
      edges.push({ kind: "logged_in", from: identity, to: host, at });
    }
  }

  return { nodes, edges };
}

/** Folds many per-host events into one deduplicated graph: for a repeated
 * node or edge, the fact with the latest `at` wins — deterministic
 * regardless of the order `parts` is given in, unlike picking whichever
 * happened to be seen last in that particular iteration. */
export function mergeGraphs(parts: Graph[]): Graph {
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  for (const part of parts) {
    for (const node of part.nodes) {
      const id = nodeId(node);
      const seen = nodes.get(id);
      if (!seen || node.at > seen.at) nodes.set(id, node);
    }
    for (const edge of part.edges) {
      const id = edgeId(edge);
      const seen = edges.get(id);
      if (!seen || edge.at > seen.at) edges.set(id, edge);
    }
  }
  return { nodes: Array.from(nodes.values()), edges: Array.from(edges.values()) };
}

/**
 * A case's subgraph: every node and edge implied by its detections' events.
 * Computed fresh from the rows the caller already fetched for the case —
 * nothing is read or written beyond that.
 */
export function caseSubgraph(detections: { agentId: string; event: unknown; timestamp: Date }[]): Graph {
  return mergeGraphs(detections.map((d) => extractGraphFacts(d.agentId, d.event, d.timestamp)));
}

/**
 * "Everywhere this hash ran": one `file` node and one `host` node per agent
 * that showed it, from already-queried `PrevalenceSighting` rows for a single
 * `(kind, key)` — cheaper and wider than replaying `Detection` rows, since
 * prevalence counts every execution, not just the ones that fired a rule.
 * `kind` is widened beyond `sha256` to any prevalence kind the caller already
 * has sightings for (`image_path`, `domain`), rendered as a `file`/`network`
 * node respectively — same two node kinds `extractGraphFacts` uses for them.
 */
export function hashPivot(
  kind: PrevalenceKind,
  key: string,
  sightings: { agentId: string; firstSeen: Date; lastSeen: Date; count: number }[]
): Graph {
  const subject: NodeRef =
    kind === "domain" ? { kind: "network", key: `dns:${key}` } : { kind: "file", key: `${kind}:${key}` };
  const latest = sightings.reduce((max, s) => (s.lastSeen > max ? s.lastSeen : max), sightings[0]?.lastSeen ?? new Date(0));
  const nodes: GraphNode[] = [{ ...subject, label: key, attrs: { kind }, at: latest }];
  const edges: GraphEdge[] = [];
  for (const s of sightings) {
    const host: NodeRef = { kind: "host", key: s.agentId };
    nodes.push({ ...host, label: s.agentId, attrs: {}, at: s.lastSeen });
    edges.push({ kind: "ran_on", from: subject, to: host, at: s.lastSeen });
  }
  return { nodes, edges };
}

/** Narrows a `Graph` to what a console needs to draw it, in a stable order
 * (nodes by id, edges by id) so two computations of the same facts compare
 * equal regardless of input order — the property `rebuildGraph` tests. */
export function sortGraph(graph: Graph): Graph {
  return {
    nodes: [...graph.nodes].sort((a, b) => nodeId(a).localeCompare(nodeId(b))),
    edges: [...graph.edges].sort((a, b) => edgeId(a).localeCompare(edgeId(b))),
  };
}
