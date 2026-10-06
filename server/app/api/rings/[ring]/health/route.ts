import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";

const VALID_RINGS = ["canary_0", "canary_1", "canary_2", "prod"];
const SILENCE_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes

/**
 * GET /api/rings/{ring}/health
 * Admin endpoint: Get health metrics for a ring
 *
 * Authentication: better-auth session
 * Response: {
 *   ring: string,
 *   totalAgents: number,
 *   healthyAgents: number,
 *   silentAgents: number,
 *   silentRate: number,
 *   contentRelease: { releaseVersion, status, releasedAt } for the latest release,
 *   recentDetections: number,
 *   falsePositives: number
 * }
 */
export async function GET(
  req: NextRequest,
  { params }: { params: { ring: string } }
) {
  try {
    const tenantId = await getTenantId(req);
    const { ring } = params;

    // Validate ring parameter
    if (!VALID_RINGS.includes(ring)) {
      return NextResponse.json(
        { error: "Invalid ring", validRings: VALID_RINGS },
        { status: 400 }
      );
    }

    // Count agents in ring
    const totalAgents = await prisma.agent.count({
      where: { tenantId, ring },
    });

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

    // Report the latest release, including halted and rolled-back releases, so
    // this endpoint does not hide a halt by showing the previous active row.
    const contentRelease = await prisma.contentRelease.findFirst({
      where: {
        tenantId,
        ring,
      },
      orderBy: { releaseVersion: "desc" },
      select: {
        releaseVersion: true,
        status: true,
        releasedAt: true,
      },
    });

    // Get agents in this ring
    const agents = await prisma.agent.findMany({
      where: { tenantId, ring },
      select: { id: true },
    });
    const agentIds = agents.map((a) => a.id);

    // Count recent detections from agents in this ring (last 24 hours)
    const recentDetections = await prisma.detection.count({
      where: {
        tenantId,
        agentId: { in: agentIds },
        timestamp: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000),
        },
      },
    });

    // Count false positives (detections with severity "low" as proxy - needs better tracking)
    const falsePositives = await prisma.detection.count({
      where: {
        tenantId,
        agentId: { in: agentIds },
        timestamp: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000),
        },
        severity: "low", // Placeholder - real FP tracking needs dedicated field
      },
    });

    return NextResponse.json({
      ring,
      totalAgents,
      healthyAgents,
      silentAgents,
      silentRate: Math.round(silentRate * 100) / 100,
      contentRelease,
      recentDetections,
      falsePositives,
      healthStatus:
        silentRate > 0.05
          ? "unhealthy"
          : silentRate > 0.02
          ? "degraded"
          : "healthy",
    });
  } catch (error) {
    console.error("Ring health query error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
