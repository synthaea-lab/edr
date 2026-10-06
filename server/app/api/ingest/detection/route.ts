import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { extractEnrollmentId, verifyProxyAuth } from "@/lib/tenant";
import { z } from "zod";
import { createHash } from "node:crypto";
import { extractObservations, recordObservations } from "@/lib/prevalence";
import { parseDetectionPayload } from "@/lib/detection-payload";

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

    // Find agent (with tenant context)
    const agent = await prisma.agent.findUnique({
      where: { enrollmentId },
      include: { tenant: true },
    });

    if (!agent) {
      return NextResponse.json(
        { error: "Agent not enrolled" },
        { status: 403 }
      );
    }

    // Parse and validate detection payload
    const body = await req.json();
    const detection = parseDetectionPayload(body);
    const rawIngestId = req.headers.get("Idempotency-Key");
    const ingestId = rawIngestId === null ? null : z.string().uuid().parse(rawIngestId);
    const ingestPayloadHash = ingestId === null
      ? null
      : createHash("sha256").update(JSON.stringify(body)).digest("hex");

    // Store detection
    try {
      await prisma.detection.create({
        data: {
          tenantId: agent.tenantId,
          agentId: agent.id,
          ingestId,
          ingestPayloadHash,
          timestamp: detection.timestamp,
          technique: detection.technique,
          severity: detection.severity,
          event: detection.event,
          meta: detection.meta,
        },
      });
    } catch (error) {
      if (ingestId === null || !isUniqueViolation(error)) throw error;
      const existing = await prisma.detection.findUnique({
        where: { agentId_ingestId: { agentId: agent.id, ingestId } },
        select: { ingestPayloadHash: true },
      });
      if (!existing || existing.ingestPayloadHash !== ingestPayloadHash) {
        return NextResponse.json(
          { error: "Idempotency key reused for a different detection" },
          { status: 409 }
        );
      }
      await prisma.agent.update({
        where: { id: agent.id },
        data: { lastSeen: new Date() },
      });
      return NextResponse.json({ status: "accepted" });
    }

    // Fleet prevalence (issue #76). Best effort: the detection is already
    // stored, and a counter failure must not make the agent retry and
    // duplicate it.
    try {
      await recordObservations(
        prisma,
        agent.tenantId,
        agent.id,
        detection.timestamp,
        extractObservations(detection.event)
      );
    } catch (error) {
      console.error("Prevalence update failed:", error);
    }

    // Update agent last-seen timestamp
    await prisma.agent.update({
      where: { id: agent.id },
      data: { lastSeen: new Date() },
    });

    return NextResponse.json({ status: "accepted" });
  } catch (error) {
    console.error("Detection ingest error:", error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid payload", details: error.errors },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null
    && "code" in error && error.code === "P2002";
}
