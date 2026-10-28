import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { requireTenantAdmin } from "@/lib/admin-auth";
import { z } from "zod";

const RingAssignmentSchema = z.object({
  ring: z.enum(["canary_0", "canary_1", "canary_2", "prod"]),
});

/**
 * POST /api/agents/{agentId}/ring
 * Assign an agent to a canary ring (admin-only, tenant-scoped)
 *
 * Authentication: better-auth session, `owner` or `admin` member of the tenant (#837)
 * Request body: { ring: "canary_0" | "canary_1" | "canary_2" | "prod" }
 * Response: { status: "ok", agent: Agent, previousRing: string }
 */
export async function POST(
  req: NextRequest,
  { params }: { params: { agentId: string } }
) {
  try {
    const authed = await requireTenantAdmin(req);
    if ("response" in authed) return authed.response;
    const { tenantId, userId } = authed;
    const { agentId } = params;

    // Parse request body
    const body = await req.json();
    const validation = RingAssignmentSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json(
        { error: "Invalid request", details: validation.error.errors },
        { status: 400 }
      );
    }

    const { ring } = validation.data;

    // Find agent (tenant-scoped)
    const agent = await prisma.agent.findFirst({
      where: {
        id: agentId,
        tenantId,
      },
    });

    if (!agent) {
      return NextResponse.json(
        { error: "Agent not found" },
        { status: 404 }
      );
    }

    const previousRing = agent.ring;

    // Update agent ring
    const updatedAgent = await prisma.agent.update({
      where: { id: agentId },
      data: { ring },
    });

    // Create audit log
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "agent.ring.assignment",
        resource: `agents/${agentId}`,
        details: {
          agentId,
          enrollmentId: agent.enrollmentId,
          hostname: agent.hostname,
          previousRing,
          newRing: ring,
        },
      },
    });

    return NextResponse.json({
      status: "ok",
      agent: updatedAgent,
      previousRing,
    });
  } catch (error) {
    console.error("Ring assignment error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * GET /api/agents/{agentId}/ring
 * Query current ring assignment for an agent
 *
 * Response: { ring: string, assignedAt: string }
 */
export async function GET(
  req: NextRequest,
  { params }: { params: { agentId: string } }
) {
  try {
    const tenantId = await getTenantId(req);
    const { agentId } = params;

    const agent = await prisma.agent.findFirst({
      where: {
        id: agentId,
        tenantId,
      },
      select: {
        ring: true,
        createdAt: true,
      },
    });

    if (!agent) {
      return NextResponse.json(
        { error: "Agent not found" },
        { status: 404 }
      );
    }

    return NextResponse.json({
      ring: agent.ring,
      assignedAt: agent.createdAt.toISOString(),
    });
  } catch (error) {
    console.error("Ring query error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
