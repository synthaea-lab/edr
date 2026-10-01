import { NextRequest, NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import { loadActiveManifest } from "@/lib/active-content-manifest";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

/**
 * GET /api/content/artifact?path={path}[&sha256={hex}]
 * Agent endpoint: Download one content artifact (rule, model, policy)
 *
 * Only paths listed in the agent's own active manifest are served (an
 * allowlist, not a traversal filter): `storage/artifacts` holds every tenant's
 * and ring's files, so a bare path lookup would let any enrolled agent read
 * another tenant's content or a ring's unreleased files. The stored file must
 * hash to the manifest's signed value before it is sent.
 *
 * Authentication: nginx proxy secret + mTLS + enrolled agent (`authenticateAgent`)
 * Query params:
 * - path: Artifact path as the manifest lists it (e.g., "rules/beacon.sigma")
 * - sha256: Optional expected hash (hex); must equal the manifest's
 *
 * Response: Binary artifact with Content-Type header
 */
export async function GET(req: NextRequest) {
  try {
    const authenticated = await authenticateAgent(req);
    if ("response" in authenticated) return authenticated.response;
    const { agent } = authenticated;

    const { searchParams } = new URL(req.url);
    const artifactPath = searchParams.get("path");
    const expectedSha256 = searchParams.get("sha256");

    if (!artifactPath) {
      return NextResponse.json(
        { error: "Missing 'path' query parameter" },
        { status: 400 }
      );
    }

    const active = await loadActiveManifest(agent);
    if (!active.ok) {
      return NextResponse.json({ error: active.error }, { status: active.status });
    }
    const entry = active.manifest.entries.find((e) => e.path === artifactPath);
    if (!entry) {
      return NextResponse.json({ error: "Artifact not found" }, { status: 404 });
    }

    if (expectedSha256 && expectedSha256 !== entry.sha256) {
      return NextResponse.json(
        { error: "Hash mismatch", expected: expectedSha256, actual: entry.sha256 },
        { status: 409 }
      );
    }

    // The manifest is signed but its entry paths are not trusted as filesystem
    // paths: keep the traversal guard as defense in depth.
    if (artifactPath.includes("..") || artifactPath.startsWith("/")) {
      return NextResponse.json({ error: "Invalid artifact path" }, { status: 400 });
    }

    // TODO: Fetch from object store in production
    // For now, serve from local filesystem (dev only)
    let fileBuffer: Buffer;
    try {
      fileBuffer = await fs.readFile(path.join(process.cwd(), "storage", "artifacts", artifactPath));
    } catch (error: any) {
      if (error.code === "ENOENT") {
        return NextResponse.json({ error: "Artifact not found" }, { status: 404 });
      }
      throw error;
    }

    const actualSha256 = crypto.createHash("sha256").update(fileBuffer).digest("hex");
    if (actualSha256 !== entry.sha256) {
      console.error(
        `Stored artifact ${artifactPath} does not match the manifest: expected ${entry.sha256}, got ${actualSha256}`
      );
      return NextResponse.json({ error: "Stored artifact failed integrity check" }, { status: 502 });
    }

    const ext = path.extname(artifactPath);
    let contentType = "application/octet-stream";
    if (ext === ".sigma" || ext === ".yaml" || ext === ".yml") {
      contentType = "application/x-yaml";
    } else if (ext === ".json") {
      contentType = "application/json";
    }

    return new NextResponse(new Uint8Array(fileBuffer), {
      status: 200,
      headers: {
        "Content-Type": contentType,
        "Content-Length": fileBuffer.length.toString(),
        "X-Content-SHA256": actualSha256,
      },
    });
  } catch (error) {
    console.error("Content artifact download error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
