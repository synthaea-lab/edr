import { NextRequest, NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { prisma } from "@/lib/prisma";
import { SnapshotManifest } from "@/lib/snapshot-manifest";

/**
 * GET /api/snapshot/manifest
 * Agent endpoint (ADR-0033): the signed manifest of the agent's own tenant's common-set
 * snapshot. 404 when none has been published (signing not configured, or no build passed the
 * guards yet): the agent keeps what it has. The agent verifies the signature against the
 * `snapshot` key; the tenant comes from the certificate, never from the request.
 *
 * Authentication: nginx proxy secret + mTLS + enrolled agent (`authenticateAgent`).
 */
export async function GET(req: NextRequest) {
  try {
    const authenticated = await authenticateAgent(req);
    if ("response" in authenticated) return authenticated.response;
    const { agent } = authenticated;

    const row = await prisma.commonSetSnapshot.findUnique({
      where: { tenantId: agent.tenantId },
      select: { manifest: true },
    });
    if (!row) return NextResponse.json({ error: "No snapshot published" }, { status: 404 });
    // A row that no longer parses is a server fault, not something to hand an agent.
    const manifest = SnapshotManifest.safeParse(row.manifest);
    if (!manifest.success) {
      console.error("Stored snapshot manifest is invalid:", manifest.error.message);
      return NextResponse.json({ error: "Internal server error" }, { status: 500 });
    }
    return NextResponse.json(manifest.data);
  } catch (error) {
    console.error("Snapshot manifest fetch error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
