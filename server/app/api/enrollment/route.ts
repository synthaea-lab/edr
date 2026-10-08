import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId, getUserId } from "@/lib/tenant";
import { z } from "zod";

const EnrollmentSchema = z.object({
  enrollmentId: z.string(),
  // Self-declared and later shown in alarms: bounded and printable.
  hostname: z
    .string()
    .max(253)
    // eslint-disable-next-line no-control-regex
    .regex(/^[^\x00-\x1f\x7f]*$/)
    .optional(),
  version: z.string().optional(),
});

export async function POST(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const userId = await getUserId(req);

    const body = await req.json();
    const { enrollmentId, hostname, version } = EnrollmentSchema.parse(body);

    // Check if agent already enrolled
    const existing = await prisma.agent.findUnique({
      where: { enrollmentId },
    });

    if (existing) {
      return NextResponse.json({
        status: "already_enrolled",
        agentId: existing.id,
        ring: existing.ring,
      });
    }

    // Enroll agent
    const agent = await prisma.agent.create({
      data: {
        tenantId,
        enrollmentId,
        hostname,
        version,
        lastSeen: new Date(),
      },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "enrollment.create",
        resource: `agents/${agent.id}`,
        details: { enrollmentId, hostname, version },
      },
    });

    return NextResponse.json({
      status: "enrolled",
      agentId: agent.id,
      ring: agent.ring,
    });
  } catch (error) {
    console.error("Enrollment error:", error);

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
