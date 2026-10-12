import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";

const RINGS = ["canary_0", "canary_1", "canary_2"];
const SILENCE_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes

// Auto-halt criteria (from ADR-0016)
const MAX_SILENT_RATE = 0.05;           // 5% silent agents
const MAX_FP_RATE_INCREASE = 2.0;       // 2× baseline FP rate
const MAX_DETECTION_RATE_DROP = 0.20;   // 20% detection rate drop

/**
 * GET /api/cron/check-ring-health
 * Cron endpoint: Check all canary ring health and auto-halt on regression
 *
 * Authentication: Bearer token (CRON_SECRET)
 * Runs every 5 minutes via external cron scheduler
 *
 * Flow:
 * 1. For each tenant + ring combination:
 * 2. Calculate health metrics: silent rate, FP rate, detection rate
 * 3. Compare against baseline (prod ring metrics)
 * 4. If regression detected → auto-halt content release
 * 5. Create case for SOC notification
 *
 * Response: { checked: number, halted: Array<{tenant, ring, reason}> }
 */
export async function GET(req: NextRequest) {
  try {
    // SECURITY: fails closed when CRON_SECRET is unset, constant-time compare.
    const denied = await verifyCronRequest(req);
    if (denied) {
      return denied;
    }

    const halted: Array<{ tenantId: string; ring: string; reason: string }> = [];
    let checked = 0;

    // Get all tenants
    const tenants = await prisma.tenant.findMany({
      select: { id: true, name: true },
    });

    for (const tenant of tenants) {
      // Calculate prod ring baseline metrics
      const prodMetrics = await calculateRingMetrics(tenant.id, "prod");

      // Check each canary ring
      for (const ring of RINGS) {
        checked++;

        // Calculate canary ring metrics
        const canaryMetrics = await calculateRingMetrics(tenant.id, ring);

        // Check for regression
        const regression = detectRegression(canaryMetrics, prodMetrics);

        if (regression) {
          // Find active content release for this ring
          const release = await prisma.contentRelease.findFirst({
            where: {
              tenantId: tenant.id,
              ring,
              status: "active",
            },
            orderBy: { releaseVersion: "desc" },
          });

          if (release) {
            // Auto-halt release
            await prisma.contentRelease.update({
              where: { id: release.id },
              data: { status: "halted" },
            });

            // Create case for SOC
            await prisma.case.create({
              data: {
                tenantId: tenant.id,
                title: `Auto-halt: ${ring} deployment regression`,
                description: `Content release v${release.releaseVersion} for ring ${ring} was automatically halted due to health regression.\n\nMetrics:\n- Silent rate: ${(canaryMetrics.silentRate * 100).toFixed(2)}% (threshold: ${(MAX_SILENT_RATE * 100).toFixed(0)}%)\n- FP rate: ${canaryMetrics.fpCount} (baseline: ${prodMetrics.fpCount}, max increase: ${MAX_FP_RATE_INCREASE}×)\n- Detection rate: ${canaryMetrics.detectionCount} (baseline: ${prodMetrics.detectionCount}, max drop: ${(MAX_DETECTION_RATE_DROP * 100).toFixed(0)}%)\n\nReason: ${regression}`,
                severity: "high",
                status: "open",
              },
            });

            // Audit log
            await prisma.auditLog.create({
              data: {
                tenantId: tenant.id,
                userId: "system",
                action: "content.release.auto_halt",
                resource: `content_releases/${release.id}`,
                details: {
                  ring,
                  releaseVersion: release.releaseVersion,
                  reason: regression,
                  metrics: {
                    canary: canaryMetrics,
                    baseline: prodMetrics,
                  },
                },
              },
            });

            halted.push({
              tenantId: tenant.id,
              ring,
              reason: regression,
            });

            console.log(`Auto-halted: tenant=${tenant.name}, ring=${ring}, reason=${regression}`);
          }
        }
      }
    }

    return NextResponse.json({
      status: "ok",
      checked,
      halted,
    });
  } catch (error) {
    console.error("Ring health check error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * Calculate health metrics for a ring
 */
async function calculateRingMetrics(tenantId: string, ring: string) {
  // Count agents in ring
  const totalAgents = await prisma.agent.count({
    where: { tenantId, ring },
  });

  if (totalAgents === 0) {
    return {
      totalAgents: 0,
      healthyAgents: 0,
      silentAgents: 0,
      silentRate: 0,
      detectionCount: 0,
      fpCount: 0,
    };
  }

  // Count healthy agents (heartbeat within last 5 minutes)
  const healthyThreshold = new Date(Date.now() - SILENCE_THRESHOLD_MS);
  const healthyAgents = await prisma.agent.count({
    where: {
      tenantId,
      ring,
      lastSeen: { gte: healthyThreshold },
    },
  });

  const silentAgents = totalAgents - healthyAgents;
  const silentRate = totalAgents > 0 ? silentAgents / totalAgents : 0;

  // Get agents in this ring
  const agents = await prisma.agent.findMany({
    where: { tenantId, ring },
    select: { id: true },
  });
  const agentIds = agents.map((a) => a.id);

  // Count recent detections (last 24 hours)
  const recentThreshold = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const detectionCount = await prisma.detection.count({
    where: {
      tenantId,
      agentId: { in: agentIds },
      timestamp: { gte: recentThreshold },
    },
  });

  // Count false positives (low-severity detections as proxy)
  // TODO: Add explicit FP flag to Detection model
  const fpCount = await prisma.detection.count({
    where: {
      tenantId,
      agentId: { in: agentIds },
      timestamp: { gte: recentThreshold },
      severity: "low",
    },
  });

  return {
    totalAgents,
    healthyAgents,
    silentAgents,
    silentRate,
    detectionCount,
    fpCount,
  };
}

/**
 * Detect regression by comparing canary metrics vs baseline (prod)
 * Returns reason string if regression detected, null otherwise
 */
function detectRegression(
  canary: ReturnType<typeof calculateRingMetrics> extends Promise<infer T> ? T : never,
  baseline: ReturnType<typeof calculateRingMetrics> extends Promise<infer T> ? T : never
): string | null {
  // Skip check if no agents in canary ring
  if (canary.totalAgents === 0) {
    return null;
  }

  // Skip check if no agents in baseline ring (can't compare)
  if (baseline.totalAgents === 0) {
    return null;
  }

  // Check 1: Silent agent rate
  if (canary.silentRate > MAX_SILENT_RATE) {
    return `Silent agent rate ${(canary.silentRate * 100).toFixed(2)}% exceeds threshold ${(MAX_SILENT_RATE * 100).toFixed(0)}%`;
  }

  // Check 2: FP rate increase (only if baseline has FPs)
  if (baseline.fpCount > 0) {
    const fpRateIncrease = canary.fpCount / baseline.fpCount;
    if (fpRateIncrease > MAX_FP_RATE_INCREASE) {
      return `FP rate increased ${fpRateIncrease.toFixed(2)}× (${canary.fpCount} vs baseline ${baseline.fpCount})`;
    }
  } else if (canary.fpCount > 10) {
    // If baseline has no FPs but canary has >10, flag it
    return `FP rate spike: ${canary.fpCount} FPs (baseline: 0)`;
  }

  // Check 3: Detection rate drop (only if baseline has detections)
  if (baseline.detectionCount > 0) {
    const detectionRateDrop = 1 - (canary.detectionCount / baseline.detectionCount);
    if (detectionRateDrop > MAX_DETECTION_RATE_DROP) {
      return `Detection rate dropped ${(detectionRateDrop * 100).toFixed(0)}% (${canary.detectionCount} vs baseline ${baseline.detectionCount})`;
    }
  }

  return null;
}
