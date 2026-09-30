import { NextRequest, NextResponse } from "next/server";
import { authenticateAgent } from "@/lib/agent-auth";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

/**
 * GET /api/content/artifact?path={path}
 * Agent endpoint: Download content artifact (rule, model, policy)
 *
 * Authentication: nginx proxy secret + mTLS + enrolled agent (`authenticateAgent`)
 * Query params:
 * - path: Artifact path (e.g., "rules/beacon.sigma")
 * - sha256: Expected SHA-256 hash (hex) for verification
 *
 * Response: Binary artifact with Content-Type header
 */
export async function GET(req: NextRequest) {
  try {
    const authenticated = await authenticateAgent(req);
    if ("response" in authenticated) return authenticated.response;

    // Parse query parameters
    const { searchParams } = new URL(req.url);
    const artifactPath = searchParams.get("path");
    const expectedSha256 = searchParams.get("sha256");

    if (!artifactPath) {
      return NextResponse.json(
        { error: "Missing 'path' query parameter" },
        { status: 400 }
      );
    }

    // Security: Prevent path traversal
    if (artifactPath.includes("..") || artifactPath.startsWith("/")) {
      return NextResponse.json(
        { error: "Invalid artifact path" },
        { status: 400 }
      );
    }

    // TODO: Fetch from object store in production
    // For now, serve from local filesystem (dev only)
    const storagePath = path.join(
      process.cwd(),
      "storage",
      "artifacts",
      artifactPath
    );

    try {
      const fileBuffer = await fs.readFile(storagePath);

      // Verify SHA-256 if provided
      if (expectedSha256) {
        const actualSha256 = crypto
          .createHash("sha256")
          .update(fileBuffer)
          .digest("hex");

        if (actualSha256 !== expectedSha256) {
          return NextResponse.json(
            {
              error: "Hash mismatch",
              expected: expectedSha256,
              actual: actualSha256,
            },
            { status: 409 }
          );
        }
      }

      // Determine Content-Type based on file extension
      const ext = path.extname(artifactPath);
      let contentType = "application/octet-stream";
      if (ext === ".sigma" || ext === ".yaml" || ext === ".yml") {
        contentType = "application/x-yaml";
      } else if (ext === ".json") {
        contentType = "application/json";
      } else if (ext === ".pkl") {
        contentType = "application/octet-stream";
      }

      return new NextResponse(fileBuffer, {
        status: 200,
        headers: {
          "Content-Type": contentType,
          "Content-Length": fileBuffer.length.toString(),
          "X-Content-SHA256": crypto
            .createHash("sha256")
            .update(fileBuffer)
            .digest("hex"),
        },
      });
    } catch (error: any) {
      if (error.code === "ENOENT") {
        return NextResponse.json(
          { error: "Artifact not found" },
          { status: 404 }
        );
      }
      throw error;
    }
  } catch (error) {
    console.error("Content artifact download error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
