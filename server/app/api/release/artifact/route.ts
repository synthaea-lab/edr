import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { authenticateAgent } from "@/lib/agent-auth";
import { loadReleaseArtifact, loadReleaseManifest } from "@/lib/release-manifest";

/**
 * GET /api/release/artifact?release_version=N&path=P[&sha256=H]
 * Agent endpoint: one file of an active binary release (ADR-0015, issue #30).
 *
 * Only paths the release's own manifest lists are served (an allowlist, not a
 * traversal filter), and only from an active release of the agent's own ring.
 * The stored file must hash to the manifest's signed value before it is sent.
 *
 * Authentication: nginx proxy secret + mTLS (see `authenticateAgent`).
 * Response: the file's bytes.
 */
export async function GET(req: NextRequest) {
  try {
    const auth = await authenticateAgent(req);
    if ("response" in auth) return auth.response;
    const { agent } = auth;

    const { searchParams } = new URL(req.url);
    const versionParam = searchParams.get("release_version");
    const entryPath = searchParams.get("path");
    const expectedSha256 = searchParams.get("sha256");

    const version = versionParam !== null && /^\d+$/.test(versionParam) ? Number(versionParam) : NaN;
    if (!Number.isSafeInteger(version) || version < 1) {
      return NextResponse.json(
        { error: "Missing or invalid 'release_version' query parameter" },
        { status: 400 }
      );
    }
    if (!entryPath) {
      return NextResponse.json({ error: "Missing 'path' query parameter" }, { status: 400 });
    }

    const release = await prisma.binaryRelease.findFirst({
      where: {
        tenantId: agent.tenantId,
        ring: agent.ring,
        releaseVersion: version,
        status: "active",
      },
    });
    if (!release) {
      return NextResponse.json({ error: "Release not available" }, { status: 404 });
    }

    const loaded = await loadReleaseManifest(release);
    if (!loaded.ok) {
      return NextResponse.json({ error: loaded.error }, { status: loaded.status });
    }

    // Own-property check: `entries` is parsed JSON, so "constructor" or
    // "__proto__" must not resolve to something inherited.
    if (!Object.hasOwn(loaded.manifest.entries, entryPath)) {
      return NextResponse.json({ error: "Artifact not found" }, { status: 404 });
    }
    const manifestSha256 = loaded.manifest.entries[entryPath];

    if (expectedSha256 && expectedSha256 !== manifestSha256) {
      return NextResponse.json(
        { error: "Hash mismatch", expected: expectedSha256, actual: manifestSha256 },
        { status: 409 }
      );
    }

    const artifact = await loadReleaseArtifact(version, entryPath, manifestSha256);
    if (!artifact.ok) {
      return NextResponse.json({ error: artifact.error }, { status: artifact.status });
    }

    return new NextResponse(new Uint8Array(artifact.bytes), {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": artifact.bytes.length.toString(),
        "X-Content-SHA256": manifestSha256,
      },
    });
  } catch (error) {
    console.error("Release artifact download error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
