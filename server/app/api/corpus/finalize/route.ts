import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireTenantAdmin } from "@/lib/admin-auth";
import { z } from "zod";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

const FinalizeSchema = z.object({
  version: z.number().int().min(1),
});

/**
 * POST /api/corpus/finalize
 * Admin endpoint: Finalize corpus version and export to JSONL
 *
 * Authentication: better-auth session, `owner` or `admin` member of the tenant (#837)
 * Request body: { version: number }
 * Response: { status: "finalized", version, sampleCount, exportUrl, exportSha256 }
 */
export async function POST(req: NextRequest) {
  try {
    const authed = await requireTenantAdmin(req);
    if ("response" in authed) return authed.response;
    const { tenantId, userId } = authed;

    // Parse request body
    const body = await req.json();
    const validation = FinalizeSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json(
        { error: "Invalid request", details: validation.error.errors },
        { status: 400 }
      );
    }

    const { version: versionNumber } = validation.data;

    // Find corpus version
    const version = await prisma.corpusVersion.findUnique({
      where: {
        tenantId_version: {
          tenantId,
          version: versionNumber,
        },
      },
    });

    if (!version) {
      return NextResponse.json(
        { error: "Corpus version not found" },
        { status: 404 }
      );
    }

    if (version.status !== "collecting") {
      return NextResponse.json(
        {
          error: "Corpus already finalized",
          message: `Version ${versionNumber} is already in status: ${version.status}`,
        },
        { status: 409 }
      );
    }

    // Fetch all samples for this version
    const samples = await prisma.corpusSample.findMany({
      where: {
        corpusVersionId: version.id,
      },
      orderBy: { timestamp: "asc" },
      select: {
        timestamp: true,
        eventType: true,
        event: true,
        agentId: true,
      },
    });

    // Export to JSONL
    const exportDir = path.join(
      process.cwd(),
      "storage",
      "corpus",
      tenantId
    );
    await fs.mkdir(exportDir, { recursive: true });

    const exportFilename = `corpus-v${versionNumber}.jsonl`;
    const exportPath = path.join(exportDir, exportFilename);

    // Write JSONL (one JSON object per line)
    const jsonlLines = samples.map((sample) =>
      JSON.stringify({
        timestamp: sample.timestamp.toISOString(),
        event_type: sample.eventType,
        event: sample.event,
        agent_id: sample.agentId,
      })
    );
    await fs.writeFile(exportPath, jsonlLines.join("\n") + "\n", "utf-8");

    // Compute SHA-256 of export file
    const fileBuffer = await fs.readFile(exportPath);
    const sha256 = crypto.createHash("sha256").update(fileBuffer).digest("hex");

    // Update corpus version with export details
    const exportUrl = `/storage/corpus/${tenantId}/${exportFilename}`;
    const finalizedVersion = await prisma.corpusVersion.update({
      where: { id: version.id },
      data: {
        status: "finalized",
        collectionEnd: new Date(),
        exportUrl,
        exportSha256: sha256,
      },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "corpus.version.finalize",
        resource: `corpus_versions/${version.id}`,
        details: {
          version: versionNumber,
          sampleCount: finalizedVersion.sampleCount,
          exportUrl,
          exportSha256: sha256,
        },
      },
    });

    return NextResponse.json({
      status: "finalized",
      version: versionNumber,
      sampleCount: finalizedVersion.sampleCount,
      exportUrl,
      exportSha256: sha256,
    });
  } catch (error) {
    console.error("Corpus finalize error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
