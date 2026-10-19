import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requireTenantAdmin } from "@/lib/admin-auth";
import { EVENTS, CRON_PERIOD_SECONDS } from "@/lib/notify/outbox";
import { sealSecret, currentKey } from "@/lib/notify/secret";
import { resendFailed } from "@/lib/notify/outbox";
import { channelView, newSigningSecret } from "@/lib/notify/channels";

const PatchSchema = z
  .object({
    action: z.enum(["enable", "disable", "rotate_secret", "update", "resend_failed"]),
    events: z.array(z.enum(EVENTS)).optional(),
    huntIds: z.array(z.string().uuid()).max(50).optional(),
    cooldownSeconds: z.number().int().min(CRON_PERIOD_SECONDS).max(86_400).optional(),
  })
  .strict();

type Ctx = { params: { id: string } };

/**
 * PATCH /api/notify/channels/{id} — tenant `owner`/`admin` only.
 * `enable` re-activates a paused or disabled channel: its kept rows are replayed oldest first.
 * `rotate_secret` returns the new secret once. `resend_failed` puts the rows marked `failed` back
 * in the queue. Every action is an AuditLog row.
 */
export async function PATCH(req: NextRequest, { params }: Ctx) {
  try {
    const authed = await requireTenantAdmin(req);
    if ("response" in authed) return authed.response;
    const { tenantId, userId } = authed;

    const parsed = PatchSchema.safeParse(await req.json().catch(() => null));
    if (!parsed.success) {
      return NextResponse.json({ error: "Invalid request", details: parsed.error.errors }, { status: 400 });
    }
    const { action, events, huntIds, cooldownSeconds } = parsed.data;

    const channel = await prisma.notificationChannel.findFirst({ where: { id: params.id, tenantId } });
    if (!channel) return NextResponse.json({ error: "Channel not found" }, { status: 404 });

    let data: Record<string, unknown> = {};
    let secret: string | undefined;
    let resent: number | undefined;
    if (action === "resend_failed") {
      // The console's "send again" (ADR-0036 point 7). A failed row that a later row of the same
      // subject has superseded stays as it is: a receiver would discard it by `seq` anyway.
      resent = await resendFailed(prisma, channel.id, new Date());
    } else if (action === "enable") data = { status: "active", pauseCountFrom: new Date() };
    else if (action === "disable") data = { status: "disabled" };
    else if (action === "rotate_secret") {
      if (!currentKey()) {
        return NextResponse.json({ error: "Notifications are not configured on this server" }, { status: 503 });
      }
      secret = newSigningSecret();
      const sealed = sealSecret(secret, channel.id)!;
      // For 24 hours both secrets sign, so a receiver that has not switched yet keeps working
      // (the header carries `v1=<new>,v1=<old>`); the delivery cron forgets the old one after.
      data = {
        secretKeyId: sealed.keyId,
        secretSealed: sealed.sealed,
        prevSecretKeyId: channel.secretKeyId,
        prevSecretSealed: channel.secretSealed,
        prevSecretUntil: new Date(Date.now() + 24 * 3_600_000),
      };
    } else {
      if (huntIds && huntIds.length > 0) {
        const own = await prisma.hunt.count({ where: { tenantId, id: { in: huntIds } } });
        if (own !== new Set(huntIds).size) return NextResponse.json({ error: "Unknown hunt" }, { status: 400 });
      }
      data = {
        ...(events ? { events } : {}),
        ...(huntIds ? { huntIds } : {}),
        ...(cooldownSeconds ? { cooldownSeconds } : {}),
      };
    }

    const updated = await prisma.notificationChannel.update({ where: { id: channel.id }, data });
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: `notify.channel.${action}`,
        resource: `notification_channels/${channel.id}`,
        // Never the secret or the URL path.
        details: {
          events: updated.events,
          huntIds: updated.huntIds,
          status: updated.status,
          ...(resent !== undefined ? { resent } : {}),
        },
      },
    });
    return NextResponse.json({
      channel: channelView(updated),
      ...(secret ? { secret, previousSecretValidUntil: data.prevSecretUntil } : {}),
      ...(resent !== undefined ? { resent } : {}),
    });
  } catch (error) {
    console.error("Update notification channel error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

/** DELETE /api/notify/channels/{id} — tenant `owner`/`admin` only. Its outbox rows go with it. */
export async function DELETE(req: NextRequest, { params }: Ctx) {
  try {
    const authed = await requireTenantAdmin(req);
    if ("response" in authed) return authed.response;
    const { tenantId, userId } = authed;

    const channel = await prisma.notificationChannel.findFirst({ where: { id: params.id, tenantId } });
    if (!channel) return NextResponse.json({ error: "Channel not found" }, { status: 404 });

    await prisma.notificationChannel.delete({ where: { id: channel.id } });
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "notify.channel.delete",
        resource: `notification_channels/${channel.id}`,
        details: { host: channel.host },
      },
    });
    return NextResponse.json({ status: "deleted" });
  } catch (error) {
    console.error("Delete notification channel error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
