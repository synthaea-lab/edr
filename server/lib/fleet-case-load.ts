import type { PrismaClient } from "@prisma/client";

/**
 * Reading fleet cases for the console and the API (#62). Every query is scoped to the tenant, so
 * another tenant's fleet case is "not found", never its contents. Server only.
 */

/** The most fleet cases one list answers; the page says when there were more. */
export const FLEET_CASE_LIST_LIMIT = 200;
/** The most detections one fleet case shows; the page says when there were more. */
export const FLEET_CASE_DETECTIONS_LIMIT = 200;

export type FleetCaseSummary = {
  id: string;
  severity: string;
  status: string;
  agentCount: number;
  detectionCount: number;
  firstAt: Date;
  lastAt: Date;
  entities: { kind: string; key: string }[];
};

export async function listFleetCases(
  db: Pick<PrismaClient, "fleetCase">,
  tenantId: string
): Promise<{ cases: FleetCaseSummary[]; truncated: boolean }> {
  const rows = await db.fleetCase.findMany({
    where: { tenantId },
    orderBy: [{ lastAt: "desc" }, { id: "asc" }],
    take: FLEET_CASE_LIST_LIMIT + 1,
    include: {
      entities: { select: { kind: true, key: true }, orderBy: [{ kind: "asc" }, { key: "asc" }] },
      _count: { select: { detections: true } },
    },
  });
  const cases = rows.slice(0, FLEET_CASE_LIST_LIMIT).map((r) => ({
    id: r.id,
    severity: r.severity,
    status: r.status,
    agentCount: r.agentCount,
    detectionCount: r._count.detections,
    firstAt: r.firstAt,
    lastAt: r.lastAt,
    entities: r.entities,
  }));
  return { cases, truncated: rows.length > FLEET_CASE_LIST_LIMIT };
}

export type FleetCaseDetail = Omit<FleetCaseSummary, "detectionCount"> & {
  agents: { id: string; hostname: string | null }[];
  detections: {
    id: string;
    agentId: string;
    timestamp: Date;
    technique: string;
    severity: string;
    caseId: string | null;
  }[];
  detectionsTruncated: boolean;
};

/** One fleet case of this tenant, or `null`. Detections are listed oldest first. */
export async function loadFleetCase(
  db: Pick<PrismaClient, "fleetCase" | "detection" | "agent">,
  tenantId: string,
  id: string
): Promise<FleetCaseDetail | null> {
  const row = await db.fleetCase.findFirst({
    where: { id, tenantId },
    include: { entities: { select: { kind: true, key: true }, orderBy: [{ kind: "asc" }, { key: "asc" }] } },
  });
  if (!row) return null;

  const found = await db.detection.findMany({
    where: { fleetCaseId: row.id, tenantId },
    orderBy: [{ timestamp: "asc" }, { id: "asc" }],
    take: FLEET_CASE_DETECTIONS_LIMIT + 1,
    select: { id: true, agentId: true, timestamp: true, technique: true, severity: true, caseId: true },
  });
  const detections = found.slice(0, FLEET_CASE_DETECTIONS_LIMIT);
  const agentIds = Array.from(new Set(detections.map((d) => d.agentId)));
  const agents = await db.agent.findMany({
    where: { id: { in: agentIds }, tenantId },
    select: { id: true, hostname: true },
    orderBy: { id: "asc" },
  });
  return {
    id: row.id,
    severity: row.severity,
    status: row.status,
    agentCount: row.agentCount,
    firstAt: row.firstAt,
    lastAt: row.lastAt,
    entities: row.entities,
    agents,
    detections,
    detectionsTruncated: found.length > FLEET_CASE_DETECTIONS_LIMIT,
  };
}
