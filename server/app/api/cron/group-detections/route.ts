import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import {
  GROUPING_BATCH_SIZE,
  isRelatedTechnique,
  outranksSeverity,
  withinTimeWindow,
} from "@/lib/case-grouping";

interface CandidateCase {
  id: string;
  severity: string;
  detections: { agentId: string; timestamp: Date; technique: string }[];
}

// Arbitrary fixed key for a transaction-scoped advisory lock. Two overlapping
// invocations of this cron (a retry, a duplicated scheduler trigger, a manual
// run overlapping the schedule) would otherwise read the same ungrouped
// detections and open cases twice; pg_try_advisory_xact_lock serializes them
// instead. Transaction-scoped, not session-scoped: it releases automatically
// when the transaction ends, including on crash, so there's no unlock path
// to remember.
const GROUPING_LOCK_KEY = 50_262_001;

/**
 * GET /api/cron/group-detections
 *
 * Cron endpoint (issue #50): groups ungrouped detections (`caseId: null`)
 * into a Case per tenant, so the case store has an evidence graph for
 * narrative generation to work from. Heuristic: same agent + related MITRE
 * technique to something already in the case, and within a 30 minute window
 * of the *case's earliest* detection (not just its most recent one, which
 * would let the window drift indefinitely as detections chain together) —
 * attaches to an existing open case; otherwise a new case is created.
 * Idempotent — re-running only ever touches detections still at
 * `caseId: null`. The whole sweep runs inside one transaction guarded by an
 * advisory lock, so overlapping invocations don't double-group.
 *
 * Batched per tenant (review, Jihair54/Sollykhan): at most
 * `GROUPING_BATCH_SIZE` ungrouped detections per tenant per invocation, so
 * one run always completes well inside the transaction timeout regardless of
 * backlog size — a large backlog drains over several cron ticks instead of
 * timing out and rolling back with no progress every time. `moreWorkLikely`
 * tells the caller whether any tenant's batch came back full (backlog
 * possibly larger than one batch) without an extra count query.
 *
 * Authentication: Bearer token (CRON_SECRET)
 * Response: { tenantsChecked, casesCreated, detectionsGrouped, moreWorkLikely }
 *   or { skipped: true } if another invocation already holds the lock.
 */
export async function GET(req: NextRequest) {
  try {
    const denied = verifyCronRequest(req);
    if (denied) {
      return denied;
    }

    const result = await prisma.$transaction(
      async (tx) => {
        const lockRows = await tx.$queryRaw<{ locked: boolean }[]>`
          SELECT pg_try_advisory_xact_lock(${GROUPING_LOCK_KEY}) AS locked
        `;
        if (!lockRows[0]?.locked) {
          return { skipped: true as const };
        }

        const tenants = await tx.tenant.findMany({ select: { id: true } });

        let casesCreated = 0;
        let detectionsGrouped = 0;
        let moreWorkLikely = false;

        for (const tenant of tenants) {
          const ungrouped = await tx.detection.findMany({
            where: { tenantId: tenant.id, caseId: null },
            orderBy: { timestamp: "asc" },
            take: GROUPING_BATCH_SIZE,
          });

          if (ungrouped.length === 0) {
            continue;
          }
          if (ungrouped.length === GROUPING_BATCH_SIZE) {
            // A full batch doesn't prove more is queued (could land exactly on
            // the cap), but it's the cheap signal available without a second
            // count query — a false positive here just costs one extra tick
            // that finds nothing left.
            moreWorkLikely = true;
          }

          const openCases: CandidateCase[] = await tx.case.findMany({
            where: { tenantId: tenant.id, status: "open" },
            select: {
              id: true,
              severity: true,
              detections: { select: { agentId: true, timestamp: true, technique: true } },
            },
          });

          const agents = await tx.agent.findMany({
            where: { tenantId: tenant.id },
            select: { id: true, hostname: true },
          });
          const hostnameByAgentId = new Map(agents.map((a) => [a.id, a.hostname]));

          // detection id -> target case id, applied as one updateMany per
          // case after the decision loop instead of one update per detection.
          const assignments = new Map<string, string[]>();

          for (const detection of ungrouped) {
            const match = openCases.find((c) => {
              if (c.detections.length === 0) {
                return false;
              }
              const caseStart = Math.min(...c.detections.map((d) => d.timestamp.getTime()));
              const sameAgentRelatedTechnique = c.detections.some(
                (d) =>
                  d.agentId === detection.agentId && isRelatedTechnique(d.technique, detection.technique)
              );
              return sameAgentRelatedTechnique && withinTimeWindow(new Date(caseStart), detection.timestamp);
            });

            let targetCase: CandidateCase;
            if (match) {
              targetCase = match;
            } else {
              const hostname = hostnameByAgentId.get(detection.agentId);
              const created = await tx.case.create({
                data: {
                  tenantId: tenant.id,
                  title: `${detection.technique} activity on ${hostname ?? detection.agentId}`,
                  severity: detection.severity,
                  status: "open",
                },
                select: { id: true, severity: true },
              });
              targetCase = { ...created, detections: [] };
              openCases.push(targetCase);
              casesCreated++;
            }

            const existing = assignments.get(targetCase.id) ?? [];
            existing.push(detection.id);
            assignments.set(targetCase.id, existing);
            detectionsGrouped++;

            if (outranksSeverity(detection.severity, targetCase.severity)) {
              await tx.case.update({
                where: { id: targetCase.id },
                data: { severity: detection.severity },
              });
              targetCase.severity = detection.severity;
            }

            targetCase.detections.push({
              agentId: detection.agentId,
              timestamp: detection.timestamp,
              technique: detection.technique,
            });
          }

          for (const [caseId, detectionIds] of Array.from(assignments)) {
            await tx.detection.updateMany({
              where: { id: { in: detectionIds } },
              data: { caseId },
            });
          }
        }

        return {
          skipped: false as const,
          tenantsChecked: tenants.length,
          casesCreated,
          detectionsGrouped,
          moreWorkLikely,
        };
      },
      { timeout: 30_000 }
    );

    if (result.skipped) {
      return NextResponse.json({ skipped: true, reason: "grouping already in progress" });
    }

    return NextResponse.json(result);
  } catch (error) {
    console.error("Detection grouping error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
