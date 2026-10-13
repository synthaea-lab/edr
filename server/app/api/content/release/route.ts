import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId, getUserId } from "@/lib/tenant";
import { z } from "zod";
import { validatePublishable } from "@/lib/content-publish";

const CreateReleaseSchema = z.object({
  ring: z.enum(["canary_0", "canary_1", "canary_2", "prod"]),
  manifestUrl: z.string().url(),
  manifestSha256: z.string().regex(/^[a-f0-9]{64}$/),
  releasedAt: z.string().datetime().optional(),
});

/**
 * POST /api/content/release
 * Admin endpoint: Create new content release for a ring
 *
 * Authentication: better-auth session (admin only)
 * Request body: { ring, manifestUrl, manifestSha256, releasedAt? }
 * Response: { release: ContentRelease }
 *
 * The release is numbered one above the ring's highest (rolled-back releases included) and
 * is refused (422) unless its manifest is the one named by `manifestUrl`/`manifestSha256`,
 * lists at least one entry, is for this ring and carries that number, and every artifact it
 * lists is in `storage/artifacts` and hashes to the manifest's value.
 */
export async function POST(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const userId = await getUserId(req);

    // Parse request body
    const body = await req.json();
    const validation = CreateReleaseSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json(
        { error: "Invalid request", details: validation.error.errors },
        { status: 400 }
      );
    }

    const { ring, manifestUrl, manifestSha256, releasedAt } = validation.data;

    // Find highest release version for this tenant + ring
    const latestRelease = await prisma.contentRelease.findFirst({
      where: { tenantId, ring },
      orderBy: { releaseVersion: "desc" },
    });

    const nextVersion = (latestRelease?.releaseVersion || 0) + 1;

    // Nothing is published that an agent could not apply: the manifest must be the one it is
    // published as and every artifact it lists must be in the store (see validatePublishable).
    const publishable = await validatePublishable({
      ring,
      releaseVersion: nextVersion,
      manifestUrl,
      manifestSha256,
    });
    if (!publishable.ok) {
      return NextResponse.json({ error: publishable.error }, { status: 422 });
    }

    // Create new release
    let release;
    try {
      release = await prisma.contentRelease.create({
        data: {
          tenantId,
          ring,
          releaseVersion: nextVersion,
          manifestUrl,
          manifestSha256,
          status: "active",
          releasedAt: releasedAt ? new Date(releasedAt) : new Date(),
        },
      });
    } catch (error) {
      // Another publish read the same highest release and took the number first (the
      // (tenant, ring, version) row is unique): the manifest signed for it is now stale.
      if ((error as { code?: string }).code === "P2002") {
        return NextResponse.json(
          { error: "Another release took this number first; rebuild the manifest for the next one" },
          { status: 409 }
        );
      }
      throw error;
    }

    // Audit log
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "content.release.create",
        resource: `content_releases/${release.id}`,
        details: {
          ring,
          releaseVersion: nextVersion,
          manifestUrl,
          entries: publishable.manifest.entries.length,
        },
      },
    });

    return NextResponse.json({
      status: "created",
      release,
    });
  } catch (error) {
    console.error("Content release creation error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * GET /api/content/release
 * Admin endpoint: List content releases for tenant
 *
 * Query params:
 * - ring: Filter by ring (optional)
 * - status: Filter by status (optional)
 * - limit: Number of results (default: 50, max: 1000)
 *
 * Response: { releases: ContentRelease[] }
 */
export async function GET(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const { searchParams } = new URL(req.url);

    const ring = searchParams.get("ring");
    const status = searchParams.get("status");
    const limit = parseInt(searchParams.get("limit") || "50", 10);

    const releases = await prisma.contentRelease.findMany({
      where: {
        tenantId,
        ...(ring && { ring }),
        ...(status && { status }),
      },
      orderBy: [{ ring: "asc" }, { releaseVersion: "desc" }],
      take: Math.min(limit, 1000),
    });

    return NextResponse.json({ releases });
  } catch (error) {
    console.error("Content releases query error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
