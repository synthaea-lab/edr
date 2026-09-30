import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { getTenantId, getUserId } from "@/lib/tenant";
import { loadReleaseArtifact, loadReleaseManifest } from "@/lib/release-manifest";

const CreateReleaseSchema = z.object({
  ring: z.enum(["canary_0", "canary_1", "canary_2", "prod"]),
  releaseVersion: z.number().int().min(1),
  manifestUrl: z.string().min(1),
  manifestSha256: z.string().regex(/^[a-f0-9]{64}$/),
  releasedAt: z.string().datetime().optional(),
});

/**
 * POST /api/release
 * Admin endpoint: publish a signed binary release to a ring (ADR-0015, #30).
 *
 * Authentication: better-auth session.
 * Request body: { ring, releaseVersion, manifestUrl, manifestSha256, releasedAt? }
 *
 * Refuses to publish anything an agent could not install: the manifest must
 * hash to `manifestSha256`, match the schema, carry `releaseVersion`, and every
 * entry's artifact must already be in storage and hash to its signed value.
 * The Ed25519 signature is not checked here (the server never holds the key);
 * every agent verifies it before staging. `releaseVersion` must be strictly
 * greater than the ring's latest, mirroring the agent's anti-rollback check.
 */
export async function POST(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const userId = await getUserId(req);

    const validation = CreateReleaseSchema.safeParse(await req.json());
    if (!validation.success) {
      return NextResponse.json(
        { error: "Invalid request", details: validation.error.errors },
        { status: 400 }
      );
    }
    const { ring, releaseVersion, manifestUrl, manifestSha256, releasedAt } = validation.data;

    const latest = await prisma.binaryRelease.findFirst({
      where: { tenantId, ring },
      orderBy: { releaseVersion: "desc" },
    });
    if (latest && releaseVersion <= latest.releaseVersion) {
      return NextResponse.json(
        {
          error: "releaseVersion must be greater than the ring's latest release",
          latest: latest.releaseVersion,
        },
        { status: 409 }
      );
    }

    const loaded = await loadReleaseManifest({
      id: "(unpublished)",
      manifestUrl,
      manifestSha256,
      releaseVersion,
    });
    if (!loaded.ok) {
      return NextResponse.json({ error: loaded.error }, { status: 422 });
    }
    for (const [entryPath, sha256] of Object.entries(loaded.manifest.entries)) {
      const artifact = await loadReleaseArtifact(releaseVersion, entryPath, sha256);
      if (!artifact.ok) {
        return NextResponse.json(
          { error: `Artifact ${JSON.stringify(entryPath)}: ${artifact.error}` },
          { status: 422 }
        );
      }
    }

    let release;
    try {
      release = await prisma.binaryRelease.create({
        data: {
          tenantId,
          ring,
          releaseVersion,
          manifestUrl,
          manifestSha256,
          status: "active",
          releasedAt: releasedAt ? new Date(releasedAt) : new Date(),
        },
      });
    } catch (error) {
      if ((error as { code?: string }).code === "P2002") {
        return NextResponse.json(
          { error: "A release with this version already exists for the ring" },
          { status: 409 }
        );
      }
      throw error;
    }

    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "release.create",
        resource: `binary_releases/${release.id}`,
        details: {
          ring,
          releaseVersion,
          manifestUrl,
          entries: Object.keys(loaded.manifest.entries).length,
        },
      },
    });

    return NextResponse.json({ status: "created", release });
  } catch (error) {
    console.error("Binary release creation error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

/**
 * GET /api/release
 * Admin endpoint: list the tenant's binary releases.
 * Query params: ring, status (optional), limit (default 50, max 1000).
 */
export async function GET(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const { searchParams } = new URL(req.url);
    const ring = searchParams.get("ring");
    const status = searchParams.get("status");
    const limit = parseInt(searchParams.get("limit") || "50", 10);

    const releases = await prisma.binaryRelease.findMany({
      where: { tenantId, ...(ring && { ring }), ...(status && { status }) },
      orderBy: [{ ring: "asc" }, { releaseVersion: "desc" }],
      take: Math.min(Number.isNaN(limit) ? 50 : limit, 1000),
    });
    return NextResponse.json({ releases });
  } catch (error) {
    console.error("Binary releases query error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
