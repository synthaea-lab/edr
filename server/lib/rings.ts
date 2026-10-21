import type { PrismaClient } from "@prisma/client";
import { FLEET_PAGE_SIZE, loadFleet, type FleetAgent } from "@/lib/fleet";
import type { FleetStatus } from "@/lib/fleet-health";

export const RINGS = ["canary_0", "canary_1", "canary_2", "prod"] as const;
export type Ring = (typeof RINGS)[number];

/**
 * Where a ring's content rollout stands, from its newest release of any status:
 * `serving` (active), `halted`, `rolled_back`, or `no_release`.
 */
export type RolloutState = "serving" | "halted" | "rolled_back" | "no_release";

export type RingStatus = {
  ring: Ring;
  rollout: RolloutState;
  /** The newest release's version, whatever its status. */
  latestVersion: number | null;
  latestReleasedAt: string | null;
  /** The version agents are offered, or null when the ring is halted. */
  servedVersion: number | null;
  /**
   * Whether a rollback has somewhere to go: the ring is serving or halted and an earlier release
   * exists (the rollback route's own condition). False otherwise, so the console does not offer a
   * rollback that can only answer 404.
   */
  hasEarlierRelease: boolean;
  agents: number;
  byStatus: Record<FleetStatus, number>;
};

function rolloutState(status: string | undefined): RolloutState {
  if (status === "active") return "serving";
  if (status === "halted") return "halted";
  if (status === "rolled_back") return "rolled_back";
  return "no_release";
}

function countByStatus(agents: FleetAgent[]): Record<FleetStatus, number> {
  const counts: Record<FleetStatus, number> = { silent: 0, degraded: 0, no_beacon: 0, healthy: 0 };
  for (const a of agents) counts[a.status] += 1;
  return counts;
}

/**
 * One entry per ring for a tenant: rollout state next to the fleet health of the
 * agents in it. Agent counts come from the dashboard's page of agents, so a tenant
 * with more than [`FLEET_PAGE_SIZE`] agents gets `truncated: true`.
 */
export async function loadRings(
  db: Pick<PrismaClient, "agent" | "contentRelease">,
  tenantId: string,
  now: Date = new Date()
): Promise<{ rings: RingStatus[]; truncated: boolean }> {
  const fleet = await loadFleet(db, tenantId, now);
  const rings: RingStatus[] = [];
  for (const ring of RINGS) {
    const latest = await db.contentRelease.findFirst({
      where: { tenantId, ring },
      orderBy: { releaseVersion: "desc" },
    });
    const served =
      latest?.status === "halted"
        ? null
        : await db.contentRelease.findFirst({
            where: { tenantId, ring, status: "active" },
            orderBy: { releaseVersion: "desc" },
          });
    // The rollback route rolls back the newest active or halted release to an earlier one of any
    // status; when the newest release is that one, an earlier row is all it needs.
    const rollable = latest?.status === "active" || latest?.status === "halted";
    const earlier = rollable
      ? await db.contentRelease.findFirst({
          where: { tenantId, ring, releaseVersion: { lt: latest.releaseVersion } },
          select: { releaseVersion: true },
        })
      : null;
    const inRing = fleet.filter((a) => a.ring === ring);
    rings.push({
      ring,
      rollout: rolloutState(latest?.status),
      latestVersion: latest?.releaseVersion ?? null,
      latestReleasedAt: latest?.releasedAt.toISOString() ?? null,
      servedVersion: served?.releaseVersion ?? null,
      hasEarlierRelease: earlier !== null,
      agents: inRing.length,
      byStatus: countByStatus(inRing),
    });
  }
  return { rings, truncated: fleet.length >= FLEET_PAGE_SIZE };
}
