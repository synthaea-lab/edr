import { extractGraphFacts } from "@/lib/graph";

/**
 * The cross-host join of #62's first box, as pure decision logic over detections already read
 * (the Prisma calls are in `app/api/cron/join-fleet-cases/route.ts`, as `lib/case-grouping.ts`
 * does for #50).
 *
 * Two detections of different agents belong to one fleet case when they carry the same entity:
 * an executed file hash, or a signed-in identity. The entities are the ones `lib/graph.ts` already
 * extracts from an event (`file` nodes keyed `sha256:`, `identity` nodes), so a fleet case and the
 * graph of its detections agree on what an entity is.
 *
 * The join is an attack surface: an attacker who can make a detection fire on a host can try to
 * link hosts they do not control into one case, and ADR-0035 Decision 6 makes a fleet case the
 * trigger of a posture overlay. So the join is deliberately narrow:
 * - only a **hash** or an **identity**, never a bare path or a technique;
 * - the generic accounts every host has (`root`, `SYSTEM`...) are not an identity worth joining on;
 * - an entity seen on more than `MAX_AGENTS_PER_ENTITY` agents joins nothing: software that is
 *   everywhere is not evidence, and one decoy hash must not link a whole fleet;
 * - sightings join only within `FLEET_JOIN_WINDOW_MS` of each other.
 */

export const FLEET_JOIN_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * More agents than this carrying one entity and the entity joins nothing. A starting point, not a
 * measured figure: no fleet larger than a lab pair has run here.
 */
export const MAX_AGENTS_PER_ENTITY = 20;

/** Accounts present on every host: signing in as one says nothing about who else did. */
const GENERIC_IDENTITIES = new Set([
  "root",
  "system",
  "nt authority\\system",
  "nt authority\\local service",
  "nt authority\\network service",
  "administrator",
  "nobody",
  "daemon",
]);

const SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** True when `candidate` is at least as severe as `current`; unknown severities never outrank a
 * known one (as `lib/case-grouping.ts`). */
export function outranksOrEqualSeverity(candidate: string, current: string): boolean {
  return (SEVERITY_RANK[candidate] ?? -1) >= (SEVERITY_RANK[current] ?? -1);
}

export type JoinKind = "sha256" | "identity";
export type JoinKey = { kind: JoinKind; key: string };

export type FleetDetection = {
  id: string;
  agentId: string;
  timestamp: Date;
  severity: string;
  event: unknown;
};

export type FleetGroup = {
  /** Sorted by kind, then key. */
  entities: JoinKey[];
  /** Sorted. At least two. */
  agentIds: string[];
  /** Sorted. */
  detectionIds: string[];
  severity: string;
  firstAt: Date;
  lastAt: Date;
};

/** The entities of one event that a fleet case may join on. Tolerant: an event of a shape this
 * does not recognise yields nothing, never an error (it is an attacker-influenced JSON). */
export function joinKeys(hostKey: string, event: unknown, at: Date): JoinKey[] {
  const keys = new Map<string, JoinKey>();
  for (const node of extractGraphFacts(hostKey, event, at).nodes) {
    if (node.kind === "file" && node.key.startsWith("sha256:")) {
      keys.set(node.key, { kind: "sha256", key: node.key.slice("sha256:".length) });
    } else if (node.kind === "identity") {
      const user = node.key.toLowerCase();
      if (!GENERIC_IDENTITIES.has(user)) keys.set(`identity:${user}`, { kind: "identity", key: user });
    }
  }
  return Array.from(keys.values());
}

const entityId = (k: JoinKey): string => `${k.kind}\u0000${k.key}`;

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Joins `detections` into groups spanning at least two agents. The result does not depend on the
 * order of the input. */
export function joinDetections(detections: FleetDetection[]): FleetGroup[] {
  const sightings = new Map<string, { key: JoinKey; detections: FleetDetection[] }>();
  for (const d of detections) {
    for (const key of joinKeys(d.agentId, d.event, d.timestamp)) {
      const id = entityId(key);
      const entry = sightings.get(id) ?? { key, detections: [] };
      entry.detections.push(d);
      sightings.set(id, entry);
    }
  }

  // Union-find over detection ids; `entities` per root collects what joined them.
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let root = x;
    while ((parent.get(root) ?? root) !== root) root = parent.get(root) as string;
    parent.set(x, root);
    return root;
  };
  const union = (a: string, b: string): void => {
    const [ra, rb] = [find(a), find(b)];
    if (ra !== rb) parent.set(compare(ra, rb) < 0 ? rb : ra, compare(ra, rb) < 0 ? ra : rb);
  };
  const joinedBy: { key: JoinKey; members: string[] }[] = [];

  for (const { key, detections: seen } of Array.from(sightings.values())) {
    if (new Set(seen.map((d) => d.agentId)).size > MAX_AGENTS_PER_ENTITY) continue;
    const ordered = [...seen].sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime() || compare(a.id, b.id)
    );
    let cluster: FleetDetection[] = [];
    const flush = (): void => {
      if (new Set(cluster.map((d) => d.agentId)).size >= 2) {
        joinedBy.push({ key, members: cluster.map((d) => d.id) });
        for (const d of cluster) union(cluster[0].id, d.id);
      }
      cluster = [];
    };
    for (const d of ordered) {
      const last = cluster[cluster.length - 1];
      if (last && d.timestamp.getTime() - last.timestamp.getTime() > FLEET_JOIN_WINDOW_MS) flush();
      cluster.push(d);
    }
    flush();
  }

  // One host's detections that both joined something, and lie within the window of each other,
  // are one thread: what joined the first and what joined the second make one group, as in an
  // intrusion that moves from host A to B by a hash and from B to C by an identity.
  const joined = new Set<string>();
  for (const { members } of joinedBy) members.forEach((id) => joined.add(id));
  const perAgent = new Map<string, FleetDetection[]>();
  detections
    .filter((d) => joined.has(d.id))
    .forEach((d) => perAgent.set(d.agentId, [...(perAgent.get(d.agentId) ?? []), d]));
  perAgent.forEach((own) => {
    own.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime() || compare(a.id, b.id));
    for (let i = 1; i < own.length; i++) {
      if (own[i].timestamp.getTime() - own[i - 1].timestamp.getTime() <= FLEET_JOIN_WINDOW_MS) {
        union(own[i - 1].id, own[i].id);
      }
    }
  });

  // Every union is done, so each root is final here.
  const entitiesByRoot = new Map<string, Map<string, JoinKey>>();
  for (const { key, members } of joinedBy) {
    const root = find(members[0]);
    const entities = entitiesByRoot.get(root) ?? new Map<string, JoinKey>();
    entities.set(entityId(key), key);
    entitiesByRoot.set(root, entities);
  }

  const result: FleetGroup[] = [];
  for (const [root, entities] of Array.from(entitiesByRoot.entries())) {
    const members = detections.filter((d) => joined.has(d.id) && find(d.id) === root);
    const times = members.map((d) => d.timestamp.getTime());
    result.push({
      entities: Array.from(entities.values()).sort(
        (a, b) => compare(a.kind, b.kind) || compare(a.key, b.key)
      ),
      agentIds: Array.from(new Set(members.map((d) => d.agentId))).sort(compare),
      detectionIds: members.map((d) => d.id).sort(compare),
      severity: members.reduce(
        (top, d) => ((SEVERITY_RANK[d.severity] ?? -1) > (SEVERITY_RANK[top] ?? -1) ? d.severity : top),
        members[0].severity
      ),
      firstAt: new Date(Math.min(...times)),
      lastAt: new Date(Math.max(...times)),
    });
  }
  return result.sort((a, b) => compare(a.agentIds.join(","), b.agentIds.join(",")));
}
