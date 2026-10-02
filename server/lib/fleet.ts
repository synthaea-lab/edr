import type { PrismaClient } from "@prisma/client";
import { fleetStatus, sensorsOf, type FleetStatus, type SensorState } from "@/lib/fleet-health";

export type FleetAgent = {
  id: string;
  hostname: string | null;
  ring: string;
  version: string | null;
  lastSeen: string;
  status: FleetStatus;
  /** Only for an agent that has sent a beacon. */
  health: {
    beaconAt: string;
    agentVersion: string;
    spoolBytes: number;
    spoolDropped: number;
    enrichDropped: number;
    sensors: SensorState[];
  } | null;
};

/** The most agents one dashboard page lists. */
export const FLEET_PAGE_SIZE = 500;

/** A tenant's agents with their latest health, worst status first. */
export async function loadFleet(
  db: Pick<PrismaClient, "agent">,
  tenantId: string,
  now: Date = new Date()
): Promise<FleetAgent[]> {
  const rows = await db.agent.findMany({
    where: { tenantId },
    include: { health: true },
    orderBy: { lastSeen: "desc" },
    take: FLEET_PAGE_SIZE,
  });
  const order: Record<FleetStatus, number> = { silent: 0, degraded: 1, no_beacon: 2, healthy: 3 };
  return rows
    .map((a): FleetAgent => {
      const sensors = a.health ? sensorsOf(a.health.sensors) : [];
      return {
        id: a.id,
        hostname: a.hostname,
        ring: a.ring,
        version: a.version,
        lastSeen: a.lastSeen.toISOString(),
        status: fleetStatus(a, a.health ? { sensors } : null, now),
        health: a.health && {
          beaconAt: a.health.beaconAt.toISOString(),
          agentVersion: a.health.agentVersion,
          spoolBytes: Number(a.health.spoolBytes),
          spoolDropped: Number(a.health.spoolDropped),
          enrichDropped: Number(a.health.enrichDropped),
          sensors,
        },
      };
    })
    .sort((x, y) => order[x.status] - order[y.status]);
}
