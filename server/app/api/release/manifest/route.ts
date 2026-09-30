import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { authenticateAgent } from "@/lib/agent-auth";
import { loadReleaseManifest } from "@/lib/release-manifest";

/**
 * GET /api/release/manifest
 * Agent endpoint: the signed binary release manifest this agent is offered
 * (ADR-0015, issue #30). No ring in the path: the release is the latest active
 * one for the ring the server has assigned to this agent, so an agent cannot
 * ask for another ring's release.
 *
 * Authentication: nginx proxy secret + mTLS (see `authenticateAgent`).
 * Response: ReleaseManifest JSON, exactly as signed. The agent verifies the
 * Ed25519 signature and the monotone release_version itself.
 */
export async function GET(req: NextRequest) {
  try {
    const auth = await authenticateAgent(req);
    if ("response" in auth) return auth.response;
    const { agent } = auth;

    const release = await prisma.binaryRelease.findFirst({
      where: { tenantId: agent.tenantId, ring: agent.ring, status: "active" },
      orderBy: { releaseVersion: "desc" },
    });
    if (!release) {
      return NextResponse.json(
        { error: "No binary release available for ring" },
        { status: 404 }
      );
    }

    const loaded = await loadReleaseManifest(release);
    if (!loaded.ok) {
      return NextResponse.json({ error: loaded.error }, { status: loaded.status });
    }
    return NextResponse.json(loaded.manifest);
  } catch (error) {
    console.error("Release manifest fetch error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
