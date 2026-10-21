import { createHash } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { prisma } from "@/lib/prisma";

/**
 * GET /api/snapshot/artifact[?sha256={hex}]
 * Agent endpoint (ADR-0033): the bytes of the agent's own tenant's common-set snapshot
 * (`docs/detection/common-set-snapshot-format.md`). With `sha256`, it must equal the stored
 * snapshot's, else 409: an agent that read a manifest and then a newer build replaced it gets
 * told, instead of bytes its manifest does not describe. The bytes are checked against the
 * stored hash before they are sent.
 *
 * Authentication: nginx proxy secret + mTLS + enrolled agent (`authenticateAgent`).
 */
export async function GET(req: NextRequest) {
  try {
    const authenticated = await authenticateAgent(req);
    if ("response" in authenticated) return authenticated.response;
    const { agent } = authenticated;

    const expected = new URL(req.url).searchParams.get("sha256");
    const row = await prisma.commonSetSnapshot.findUnique({
      where: { tenantId: agent.tenantId },
      select: { sha256: true, artifact: true },
    });
    if (!row) return NextResponse.json({ error: "No snapshot published" }, { status: 404 });
    if (expected !== null && expected !== row.sha256) {
      return NextResponse.json({ error: "Hash mismatch", actual: row.sha256 }, { status: 409 });
    }
    const bytes = Buffer.from(row.artifact);
    if (createHash("sha256").update(bytes).digest("hex") !== row.sha256) {
      console.error("Stored snapshot does not match its hash");
      return NextResponse.json({ error: "Internal server error" }, { status: 500 });
    }
    return new NextResponse(bytes, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(bytes.length),
        "X-Content-SHA256": row.sha256,
      },
    });
  } catch (error) {
    console.error("Snapshot artifact fetch error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
