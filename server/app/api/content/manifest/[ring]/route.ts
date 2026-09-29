import crypto from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { extractEnrollmentId } from "@/lib/tenant";
import { ContentManifest, loadManifestBytes } from "@/lib/content-manifest";

const VALID_RINGS = ["canary_0", "canary_1", "canary_2", "prod"];

/**
 * GET /api/content/manifest/{ring}
 * Agent endpoint: Fetch latest content manifest for assigned ring
 *
 * Authentication: mTLS (X-Client-Cert-Verified + X-Client-Cert-Subject)
 * Response: ContentManifest JSON (signed)
 */
export async function GET(
  req: NextRequest,
  { params }: { params: { ring: string } }
) {
  try {
    // Verify mTLS authentication
    const certVerified = req.headers.get("X-Client-Cert-Verified");
    const certSubject = req.headers.get("X-Client-Cert-Subject");

    if (certVerified !== "SUCCESS" || !certSubject) {
      return NextResponse.json(
        { error: "Unauthorized - mTLS authentication required" },
        { status: 401 }
      );
    }

    const enrollmentId = extractEnrollmentId(certSubject);
    if (!enrollmentId) {
      return NextResponse.json(
        { error: "Invalid certificate subject" },
        { status: 400 }
      );
    }

    // Validate ring parameter
    const { ring } = params;
    if (!VALID_RINGS.includes(ring)) {
      return NextResponse.json(
        { error: "Invalid ring", validRings: VALID_RINGS },
        { status: 400 }
      );
    }

    // Find agent to get tenant context
    const agent = await prisma.agent.findUnique({
      where: { enrollmentId },
      select: { id: true, tenantId: true, ring: true },
    });

    if (!agent) {
      return NextResponse.json(
        { error: "Agent not enrolled" },
        { status: 403 }
      );
    }

    // Verify agent is in requested ring (prevent ring spoofing)
    if (agent.ring !== ring) {
      return NextResponse.json(
        {
          error: "Ring mismatch",
          message: `Agent is assigned to ring '${agent.ring}', cannot fetch manifest for '${ring}'`,
        },
        { status: 403 }
      );
    }

    // Find latest active content release for this tenant + ring
    const release = await prisma.contentRelease.findFirst({
      where: {
        tenantId: agent.tenantId,
        ring,
        status: "active",
      },
      orderBy: { releaseVersion: "desc" },
    });

    if (!release) {
      return NextResponse.json(
        { error: "No content release available for ring" },
        { status: 404 }
      );
    }

    // Fetch the manifest bytes the release points at (storage:// locally,
    // a real object store URL in production — see loadManifestBytes) and
    // verify integrity before trusting the content at all.
    let manifestBytes: Buffer;
    try {
      manifestBytes = await loadManifestBytes(release.manifestUrl);
    } catch (error) {
      console.error("Content manifest fetch error:", error);
      return NextResponse.json(
        { error: "Manifest artifact unavailable" },
        { status: 502 }
      );
    }

    const actualSha256 = crypto.createHash("sha256").update(manifestBytes).digest("hex");
    if (actualSha256 !== release.manifestSha256) {
      console.error(
        `Manifest integrity mismatch for release ${release.id}: expected ${release.manifestSha256}, got ${actualSha256}`
      );
      return NextResponse.json(
        { error: "Manifest integrity check failed" },
        { status: 502 }
      );
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(manifestBytes.toString("utf-8"));
    } catch {
      return NextResponse.json({ error: "Manifest is not valid JSON" }, { status: 502 });
    }

    const validation = ContentManifest.safeParse(parsed);
    if (!validation.success) {
      console.error("Content manifest shape validation error:", validation.error);
      return NextResponse.json(
        { error: "Manifest does not match the expected schema" },
        { status: 502 }
      );
    }

    const manifest = validation.data;
    if (manifest.ring !== ring) {
      // The manifest itself disagrees with the release row it was looked up
      // from — a mismatch between what was signed and what's stored, never
      // expected from this route's own release creation path.
      console.error(
        `Manifest ring mismatch for release ${release.id}: row says ${ring}, manifest says ${manifest.ring}`
      );
      return NextResponse.json({ error: "Manifest ring mismatch" }, { status: 502 });
    }
    if (manifest.release_version !== release.releaseVersion) {
      console.error(
        `Manifest release_version mismatch for release ${release.id}: row says ${release.releaseVersion}, manifest says ${manifest.release_version}`
      );
      return NextResponse.json(
        { error: "Manifest release_version mismatch" },
        { status: 502 }
      );
    }

    return NextResponse.json(manifest);
  } catch (error) {
    console.error("Content manifest fetch error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
