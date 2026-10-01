import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { extractEnrollmentId, verifyProxyAuth } from "@/lib/tenant";
import { beaconTime, parseHeartbeatBody } from "@/lib/health-beacon";

export async function POST(req: NextRequest) {
  try {
    // SECURITY: Verify request came through nginx proxy
    // Prevents header spoofing attacks
    try {
      verifyProxyAuth(req);
    } catch (error) {
      console.error("Proxy auth failed:", error);
      return NextResponse.json(
        { error: "Forbidden - invalid proxy authentication" },
        { status: 403 }
      );
    }

    // Verify mTLS authentication
    const certVerified = req.headers.get("X-Client-Cert-Verified");
    const certSubject = req.headers.get("X-Client-Cert-Subject");

    if (certVerified !== "SUCCESS" || !certSubject) {
      return NextResponse.json(
        { error: "Unauthorized - mTLS authentication required" },
        { status: 401 }
      );
    }

    // Extract agent enrollment ID from certificate
    const enrollmentId = extractEnrollmentId(certSubject);

    if (!enrollmentId) {
      return NextResponse.json(
        { error: "Invalid certificate subject" },
        { status: 400 }
      );
    }

    // Update last-seen timestamp
    const agent = await prisma.agent.update({
      where: { enrollmentId },
      data: { lastSeen: new Date() },
    });

    await storeBeacon(req, agent);

    return NextResponse.json({
      status: "ok",
      agentId: agent.id,
      ring: agent.ring,
      lastSeen: agent.lastSeen.toISOString(),
    });
  } catch (error) {
    console.error("Heartbeat error:", error);

    // Agent not found
    if ((error as any).code === "P2025") {
      return NextResponse.json(
        { error: "Agent not enrolled" },
        { status: 403 }
      );
    }

    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * Keeps the agent's latest health beacon (issue #83). Never fails the
 * heartbeat: the liveness update above already happened, and a missing,
 * malformed or unstorable beacon must not make a live agent look dead.
 */
async function storeBeacon(
  req: NextRequest,
  agent: { id: string; tenantId: string }
): Promise<void> {
  try {
    const body = await req.json().catch(() => null);
    const beacon = parseHeartbeatBody(body);
    if (!beacon) return;

    const fields = {
      beaconAt: beaconTime(beacon),
      receivedAt: new Date(),
      agentVersion: beacon.agent_version,
      spoolBytes: BigInt(beacon.spool_bytes),
      spoolDropped: BigInt(beacon.spool_dropped),
      enrichDropped: BigInt(beacon.enrich_dropped),
      sensors: beacon.sensors,
    };
    await prisma.agentHealth.upsert({
      where: { agentId: agent.id },
      create: { agentId: agent.id, tenantId: agent.tenantId, ...fields },
      update: fields,
    });
  } catch (error) {
    console.error("Health beacon store error:", error);
  }
}
