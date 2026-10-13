import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId, getUserId } from "@/lib/tenant";
import { z } from "zod";
import { correctiveReleaseAdvice } from "@/lib/content-rollback";

const RollbackSchema = z.object({
  ring: z.enum(["canary_0", "canary_1", "canary_2", "prod"]),
  targetVersion: z.number().int().min(1).optional(),
  reason: z.string().optional(),
});

/**
 * POST /api/content/rollback
 * Admin endpoint: Rollback content deployment to previous version
 *
 * Marks current release as "rolled_back" and activates a previous release.
 * If targetVersion is not specified, rolls back to the immediate previous version.
 *
 * This only helps agents that have not applied the rolled-back release yet: an agent never
 * goes to a lower release number, so one that already applied it stays on it (ADR-0032). The
 * response says so and names the corrective release that withdraws the content from them.
 *
 * Authentication: better-auth session (admin only)
 * Request body: { ring, targetVersion?, reason? }
 * Response: { status: "rolled_back", previousRelease, activeRelease, correctiveRelease }
 */
export async function POST(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const userId = await getUserId(req);

    // Parse request body
    const body = await req.json();
    const validation = RollbackSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json(
        { error: "Invalid request", details: validation.error.errors },
        { status: 400 }
      );
    }

    const { ring, targetVersion, reason } = validation.data;

    // Find current active/halted release
    const currentRelease = await prisma.contentRelease.findFirst({
      where: {
        tenantId,
        ring,
        status: { in: ["active", "halted"] },
      },
      orderBy: { releaseVersion: "desc" },
    });

    if (!currentRelease) {
      return NextResponse.json(
        { error: "No current release found for ring" },
        { status: 404 }
      );
    }

    // Find target release (either specified or previous)
    const targetRelease = await prisma.contentRelease.findFirst({
      where: {
        tenantId,
        ring,
        releaseVersion: targetVersion || {
          lt: currentRelease.releaseVersion,
        },
      },
      orderBy: { releaseVersion: "desc" },
    });

    if (!targetRelease) {
      return NextResponse.json(
        { error: "No previous release found to rollback to" },
        { status: 404 }
      );
    }

    // Prevent rolling back to same version
    if (targetRelease.id === currentRelease.id) {
      return NextResponse.json(
        { error: "Cannot rollback to current version" },
        { status: 400 }
      );
    }

    // The corrective release must beat every release of the ring, not only the active one.
    const highest = await prisma.contentRelease.findFirst({
      where: { tenantId, ring },
      orderBy: { releaseVersion: "desc" },
      select: { releaseVersion: true },
    });
    const advice = correctiveReleaseAdvice(
      highest?.releaseVersion ?? currentRelease.releaseVersion,
      targetRelease.releaseVersion,
    );

    // Mark current release as rolled_back
    const rolledBackRelease = await prisma.contentRelease.update({
      where: { id: currentRelease.id },
      data: { status: "rolled_back" },
    });

    // Activate target release
    const activatedRelease = await prisma.contentRelease.update({
      where: { id: targetRelease.id },
      data: { status: "active" },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "content.release.rollback",
        resource: `content_releases/${currentRelease.id}`,
        details: {
          ring,
          fromVersion: currentRelease.releaseVersion,
          toVersion: targetRelease.releaseVersion,
          reason: reason || "Manual rollback",
          correctiveReleaseVersion: advice.releaseVersion,
        },
      },
    });

    return NextResponse.json({
      status: "rolled_back",
      previousRelease: rolledBackRelease,
      activeRelease: activatedRelease,
      correctiveRelease: advice,
    });
  } catch (error) {
    console.error("Content rollback error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
