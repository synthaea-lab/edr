import { NextRequest, NextResponse } from "next/server";
import { mkdir, rename, writeFile } from "fs/promises";
import path from "path";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requireTenantAdmin } from "@/lib/admin-auth";
import { buildIocStage, type StagedArtifact } from "@/lib/ioc-stage";

const Kind = z.enum(["sha256", "ip", "domain"]);
const Column = z.union([z.string().min(1).max(128), z.number().int().nonnegative()]);

const StageSchema = z.object({
  feed: z.string().min(1).max(64),
  version: z.string().min(1).max(64).optional(),
  allowEmpty: z.boolean().optional(),
  source: z.discriminatedUnion("format", [
    z.object({ format: z.literal("plain"), text: z.string(), defaultKind: Kind.optional() }),
    z.object({
      format: z.literal("csv"),
      csv: z.string(),
      valueColumn: Column,
      typeColumn: Column.optional(),
      defaultKind: Kind.optional(),
      hasHeader: z.boolean().optional(),
    }),
  ]),
});

/**
 * Puts one artifact in the content-addressed store (`storage/artifacts/<sha256>`, #804), the
 * step docs/operations/content.md does by hand with `cp`. The name is the hash of the bytes, so
 * writing the same bytes twice is the same file and a different feed can never land on it. The
 * write goes through a temporary name and a rename: an agent fetching mid-write never reads half
 * a feed.
 */
async function stage(artifactsDir: string, { entry, bytes }: StagedArtifact): Promise<void> {
  const dest = path.join(artifactsDir, entry.sha256);
  const tmp = `${dest}.${process.pid}.tmp`;
  await writeFile(tmp, bytes);
  await rename(tmp, dest);
}

/**
 * POST /api/content/ioc-feed
 * Admin endpoint: build an IOC feed from a source and stage it in the artifact store.
 *
 * Authentication: better-auth session, `owner` or `admin` member of the tenant (#803)
 * Request body: { feed, version?, allowEmpty?, source } where `source` is
 *   { format: "plain", text, defaultKind? } or
 *   { format: "csv", csv, valueColumn, typeColumn?, defaultKind?, hasHeader? }
 * Response: { status: "staged", entries, report }
 *
 * This does not publish anything. It writes the feed (and `ioc/VERSION` when `version` is given)
 * to `storage/artifacts/<sha256>` and answers the manifest entries that list them, ready to go
 * into the unsigned content manifest the operator signs offline; `POST /api/content/release`
 * then checks the release as it checks every other (a feed with a line the device would skip, or
 * an `ioc/` path that is not an `ioc` entry, is refused there, 422). Refuses (422) a source that
 * leaves no indicator unless `allowEmpty` says an empty feed is the intent: it would unload the
 * set on every agent of the ring.
 */
export async function POST(req: NextRequest) {
  try {
    const authed = await requireTenantAdmin(req);
    if ("response" in authed) return authed.response;
    const { tenantId, userId } = authed;

    const validation = StageSchema.safeParse(await req.json());
    if (!validation.success) {
      return NextResponse.json({ error: "Invalid request", details: validation.error.errors }, { status: 400 });
    }

    const staged = buildIocStage(validation.data);
    if (!staged.ok) return NextResponse.json({ error: staged.error }, { status: 422 });

    const artifactsDir = path.join(process.cwd(), "storage", "artifacts");
    await mkdir(artifactsDir, { recursive: true });
    for (const item of staged.artifacts) await stage(artifactsDir, item);

    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "content.ioc_feed.stage",
        resource: `content_artifacts/${staged.artifacts[0].entry.sha256}`,
        details: {
          feed: validation.data.feed,
          version: validation.data.version ?? null,
          entries: staged.artifacts.map((a) => ({ path: a.entry.path, sha256: a.entry.sha256, size: a.entry.size })),
          counts: staged.report.counts,
          rejected: staged.report.rejectedTotal,
        },
      },
    });

    return NextResponse.json({
      status: "staged",
      entries: staged.artifacts.map((a) => a.entry),
      report: staged.report,
    });
  } catch (error) {
    console.error("IOC feed staging error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
