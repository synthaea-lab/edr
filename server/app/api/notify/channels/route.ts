import { randomUUID } from "node:crypto";
import { Prisma } from "@prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requireTenantAdmin } from "@/lib/admin-auth";
import { getTenantId } from "@/lib/tenant";
import { EVENTS, CHANNELS_PER_TENANT, CRON_PERIOD_SECONDS } from "@/lib/notify/outbox";
import { guardOptionsFromEnv, NotifyBlockedError, resolvePublicTarget } from "@/lib/notify/guard";
import { currentKey, sealSecret, sealUrl } from "@/lib/notify/secret";
import { channelView, newSigningSecret } from "@/lib/notify/channels";

const CreateSchema = z.object({
  url: z.string().url().max(2048),
  events: z.array(z.enum(EVENTS)).max(EVENTS.length).default([...EVENTS].filter((e) => e !== "hunt.new_matches")),
  huntIds: z.array(z.string().uuid()).max(50).default([]),
  cooldownSeconds: z.number().int().min(CRON_PERIOD_SECONDS).max(86_400).optional(),
});

/**
 * GET /api/notify/channels — any signed-in member: which channels exist and whether they
 * work (host only, no secret). ADR-0036 point 8.
 */
export async function GET(req: NextRequest) {
  try {
    let tenantId: string;
    try {
      tenantId = await getTenantId(req);
    } catch {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 });
    }
    const channels = await prisma.notificationChannel.findMany({
      where: { tenantId },
      orderBy: { createdAt: "asc" },
    });
    const backlog = await prisma.notification.count({
      where: { tenantId, deliveredAt: null, failedAt: null },
    });
    return NextResponse.json({ channels: channels.map(channelView), backlog });
  } catch (error) {
    console.error("List notification channels error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

/**
 * POST /api/notify/channels — tenant `owner`/`admin` only. Registers a signed webhook.
 * The signing secret is in the response once and is stored sealed.
 * Body: { url, events?, huntIds?, cooldownSeconds? }
 */
export async function POST(req: NextRequest) {
  try {
    const authed = await requireTenantAdmin(req);
    if ("response" in authed) return authed.response;
    const { tenantId, userId } = authed;

    // An unset key disables channel creation rather than storing the secret in clear.
    if (!currentKey()) {
      return NextResponse.json({ error: "Notifications are not configured on this server" }, { status: 503 });
    }

    const parsed = CreateSchema.safeParse(await req.json().catch(() => null));
    if (!parsed.success) {
      return NextResponse.json({ error: "Invalid request", details: parsed.error.errors }, { status: 400 });
    }
    const { url, events, huntIds, cooldownSeconds } = parsed.data;

    try {
      await resolvePublicTarget(url, { ...guardOptionsFromEnv(), tenantId });
    } catch (e) {
      if (e instanceof NotifyBlockedError) {
        // Coarse on purpose: the finer reason is not a port-scan oracle.
        return NextResponse.json({ error: "This URL cannot be used as a notification target" }, { status: 400 });
      }
      throw e;
    }

    if (huntIds.length > 0) {
      const own = await prisma.hunt.count({ where: { tenantId, id: { in: huntIds } } });
      if (own !== new Set(huntIds).size) {
        return NextResponse.json({ error: "Unknown hunt" }, { status: 400 });
      }
    }

    const id = randomUUID();
    const secret = newSigningSecret();
    const sealed = sealSecret(secret, id)!;
    const sealedUrl = sealUrl(url, id)!;
    // The cap is checked and the channel written under one advisory lock per tenant: two admins
    // adding the fifth and the sixth at once cannot both pass the count.
    const created = await prisma.$transaction(async (tx) => {
      await tx.$executeRaw(Prisma.sql`SELECT pg_advisory_xact_lock(hashtext(${`notify-channels:${tenantId}`}))`);
      if ((await tx.notificationChannel.count({ where: { tenantId } })) >= CHANNELS_PER_TENANT) return null;
      return tx.notificationChannel.create({
        data: {
          id,
          tenantId,
          host: new URL(url).host,
          urlKeyId: sealedUrl.keyId,
          urlSealed: sealedUrl.sealed,
          secretKeyId: sealed.keyId,
          secretSealed: sealed.sealed,
          events,
          huntIds,
          ...(cooldownSeconds ? { cooldownSeconds } : {}),
          createdBy: userId,
        },
      });
    });
    if (!created) {
      return NextResponse.json({ error: `At most ${CHANNELS_PER_TENANT} channels per tenant` }, { status: 409 });
    }
    const channel = created;

    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "notify.channel.create",
        resource: `notification_channels/${id}`,
        details: { host: new URL(url).host, events, huntIds },
      },
    });

    return NextResponse.json({ channel: channelView(channel), secret }, { status: 201 });
  } catch (error) {
    console.error("Create notification channel error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
