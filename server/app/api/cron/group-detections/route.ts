import { NextRequest, NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
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

// Fixed key for a transaction-scoped advisory lock, paired with a per-tenant
// second key (review, Jihair54): two overlapping invocations of this cron (a
// retry, a duplicated scheduler trigger, a manual run overlapping the
// schedule) would otherwise read the same tenant's ungrouped detections and
// open cases twice; pg_try_advisory_xact_lock(key, tenant_hash) serializes
// them per tenant instead of globally, so one invocation's slow tenant
// doesn't block another invocation from making progress on a different one.
// Transaction-scoped, not session-scoped: it releases automatically when the
// transaction ends, including on crash, so there's no unlock path to remember.
const GROUPING_LOCK_KEY = 50_262_001;

/** One tenant's grouping pass, or `skipped` if another invocation already
 * holds this tenant's lock. */
type TenantGroupingResult =
  | { skipped: true }
  | { skipped: false; casesCreated: number; detectionsGrouped: number; moreWorkLikely: boolean };

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
 * `caseId: null`.
 *
 * One transaction **per tenant** (review, Jihair54 — a real bug in the
 * previous batching fix): a single shared transaction across every tenant
 * meant the 30s timeout budget was `tenants × GROUPING_BATCH_SIZE` worth of
 * work, not `GROUPING_BATCH_SIZE` — with enough tenants, the shared
 * transaction still timed out and rolled back *all* of them, including
 * tenants whose own backlog was tiny, and every later tick redid the same
 * doomed work. Each tenant now gets its own transaction, its own 30s budget,
 * and its own advisory lock (`GROUPING_LOCK_KEY` + a hash of the tenant id) —
 * one tenant timing out no longer touches any other tenant's progress, this
 * tick or the next. Each tenant's transaction is also caught on its own: if
 * one still throws (a real timeout, a serialization failure), the loop moves
 * on to the remaining tenants in this same invocation instead of aborting
 * the whole request — see `tenantsFailed`.
 *
 * `moreWorkLikely` tells the caller whether any tenant's batch came back full
 * (backlog possibly larger than one batch) without an extra count query.
 *
 * Authentication: Bearer token (CRON_SECRET)
 * Response: { tenantsChecked, tenantsSkipped, tenantsFailed, casesCreated,
 *   detectionsGrouped, moreWorkLikely } — `tenantsSkipped` counts tenants
 *   another invocation already held the lock for; `tenantsFailed` counts
 *   tenants whose transaction threw. Neither is a whole-request skip.
 */
export async function GET(req: NextRequest) {
  try {
    const denied = verifyCronRequest(req);
    if (denied) {
      return denied;
    }

    const tenants = await prisma.tenant.findMany({ select: { id: true } });

    let tenantsSkipped = 0;
    let tenantsFailed = 0;
    let casesCreated = 0;
    let detectionsGrouped = 0;
    let moreWorkLikely = false;

    for (const tenant of tenants) {
      // Each tenant's transaction is caught on its own (review, Jihair54): a
      // per-tenant transaction fixes next-tick progress for other tenants,
      // but without this try/catch, one tenant's transaction throwing (a
      // real timeout, a serialization failure) would still abort this whole
      // loop and skip every tenant after it *in this same invocation* — the
      // one-slow-tenant-blocks-everyone failure mode, just moved from
      // "every tick" to "the rest of this tick".
      try {
        const result = await prisma.$transaction(
          (tx) => groupOneTenant(tx, tenant.id),
          { timeout: 30_000 }
        );

        if (result.skipped) {
          tenantsSkipped++;
          continue;
        }
        casesCreated += result.casesCreated;
        detectionsGrouped += result.detectionsGrouped;
        moreWorkLikely = moreWorkLikely || result.moreWorkLikely;
      } catch (error) {
        console.error(`Detection grouping error for tenant ${tenant.id}:`, error);
        tenantsFailed++;
      }
    }

    return NextResponse.json({
      tenantsChecked: tenants.length,
      tenantsSkipped,
      tenantsFailed,
      casesCreated,
      detectionsGrouped,
      moreWorkLikely,
    });
  } catch (error) {
    console.error("Detection grouping error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

/** Groups one tenant's ungrouped detections, inside its own transaction and
 * advisory lock — see the route doc for why this is per-tenant, not global. */
async function groupOneTenant(
  tx: Prisma.TransactionClient,
  tenantId: string
): Promise<TenantGroupingResult> {
  const lockRows = await tx.$queryRaw<{ locked: boolean }[]>`
    SELECT pg_try_advisory_xact_lock(${GROUPING_LOCK_KEY}, hashtext(${tenantId})) AS locked
  `;
  if (!lockRows[0]?.locked) {
    return { skipped: true };
  }

  const ungrouped = await tx.detection.findMany({
    where: { tenantId, caseId: null },
    orderBy: { timestamp: "asc" },
    take: GROUPING_BATCH_SIZE,
  });

  if (ungrouped.length === 0) {
    return { skipped: false, casesCreated: 0, detectionsGrouped: 0, moreWorkLikely: false };
  }
  // A full batch doesn't prove more is queued (could land exactly on the
  // cap), but it's the cheap signal available without a second count query —
  // a false positive here just costs one extra tick that finds nothing left.
  const moreWorkLikely = ungrouped.length === GROUPING_BATCH_SIZE;

  const openCases: CandidateCase[] = await tx.case.findMany({
    where: { tenantId, status: "open" },
    select: {
      id: true,
      severity: true,
      detections: { select: { agentId: true, timestamp: true, technique: true } },
    },
  });

  const agents = await tx.agent.findMany({
    where: { tenantId },
    select: { id: true, hostname: true },
  });
  const hostnameByAgentId = new Map(agents.map((a) => [a.id, a.hostname]));

  let casesCreated = 0;
  let detectionsGrouped = 0;
  // detection id -> target case id, applied as one updateMany per case after
  // the decision loop instead of one update per detection.
  const assignments = new Map<string, string[]>();

  for (const detection of ungrouped) {
    const match = openCases.find((c) => {
      if (c.detections.length === 0) {
        return false;
      }
      const caseStart = Math.min(...c.detections.map((d) => d.timestamp.getTime()));
      const sameAgentRelatedTechnique = c.detections.some(
        (d) => d.agentId === detection.agentId && isRelatedTechnique(d.technique, detection.technique)
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
          tenantId,
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

  return { skipped: false, casesCreated, detectionsGrouped, moreWorkLikely };
}
