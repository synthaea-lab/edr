import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";

const SILENCE_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes

export async function GET(req: NextRequest) {
  try {
    const denied = await verifyCronRequest(req);
    if (denied) {
      return denied;
    }

    const threshold = new Date(Date.now() - SILENCE_THRESHOLD_MS);

    // Find silent agents
    const silentAgents = await prisma.agent.findMany({
      where: {
        lastSeen: { lt: threshold },
      },
      include: { tenant: true },
    });

    let casesCreated = 0;

    // Create cases for silent agents
    for (const agent of silentAgents) {
      // Check if we already have an open case for this agent. The title carries the host
      // name when there is one, so it cannot be searched by id (#901): the description
      // always ends with the enrollment id, which is unique per agent.
      const existingCase = await prisma.case.findFirst({
        where: {
          tenantId: agent.tenantId,
          status: "open",
          OR: [
            { title: { contains: agent.id } },
            { description: { contains: `Enrollment ID: ${agent.enrollmentId}` } },
          ],
        },
      });

      if (!existingCase) {
        await prisma.case.create({
          data: {
            tenantId: agent.tenantId,
            title: `Agent Silent: ${agent.hostname || agent.id}`,
            description: `Agent has not sent heartbeat for >5 minutes. Last seen: ${agent.lastSeen.toISOString()}. Enrollment ID: ${agent.enrollmentId}`,
            severity: "high",
            status: "open",
          },
        });
        casesCreated++;
      }
    }

    return NextResponse.json({
      silentAgents: silentAgents.length,
      casesCreated,
      threshold: threshold.toISOString(),
    });
  } catch (error) {
    console.error("Silent agent detection error:", error);

    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
