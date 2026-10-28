import { Prisma, type PrismaClient } from "@prisma/client";
import type { FleetPrevalence } from "@/lib/fleet-case";
import { countReportingHosts } from "@/lib/prevalence";

/**
 * What the fleet-case join needs to know about the file hashes it may join on (#62): how many hosts
 * of the tenant have reported anything, and for each candidate hash how many of them have run it.
 * Both come from the prevalence sightings (`prevalence_sightings`, one row per `(kind, key, agent)`),
 * scoped to the tenant: another tenant's hosts are never counted. A hash with no sighting is absent
 * from the map, which the join reads as "not common".
 */
export async function loadFleetPrevalence(
  db: Pick<PrismaClient, "$queryRaw">,
  tenantId: string,
  hashes: string[]
): Promise<FleetPrevalence> {
  const reportingHosts = await countReportingHosts(db, tenantId);
  const hostsWithHash = new Map<string, number>();
  if (hashes.length > 0) {
    const rows = await db.$queryRaw<{ key: string; hosts: bigint }[]>(Prisma.sql`
      SELECT key, COUNT(DISTINCT agent_id) AS hosts
      FROM prevalence_sightings
      WHERE tenant_id = ${tenantId} AND kind = 'sha256' AND key = ANY(${hashes}::text[])
      GROUP BY key`);
    for (const row of rows) hostsWithHash.set(row.key, Number(row.hosts));
  }
  return { reportingHosts, hostsWithHash };
}
