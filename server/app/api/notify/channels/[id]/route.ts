import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requireTenantAdmin } from "@/lib/admin-auth";
import { EVENTS, CRON_PERIOD_SECONDS } from "@/lib/notify/outbox";
import { sealSecret, currentKey } from "@/lib/notify/secret";
import { channelView, newSigningSecret } from "@/lib/notify/channels";

const PatchSchema = z
  .object({
    action: z.enum(["enable", "disable", "rotate_secret", "update"]),
    events: z.array(z.enum(EVENTS)).optional(),
    huntIds: z.array(z.string().uuid()).max(50).optional(),
    cooldownSeconds: z.number().int().min(CRON_PERIOD_SECONDS).max(86_400).optional(),
  })
  .strict();

type Ctx = { params: { id: string } };

/**
 * PATCH /api/notify/channels/{id} — tenant `owner`/`admin` only.
 * `enable` re-activates a paused or disabled channel: its kept rows are replayed oldest first.
 * `rotate_secret` returns the new secret once. Every action is an AuditLog row.
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
    if (action === "enable") data = { status: "active" };
    else if (action === "disable") data = { status: "disabled" };
    else if (action === "rotate_secret") {
      if (!currentKey()) {
        return NextResponse.json({ error: "Notifications are not configured on this server" }, { status: 503 });
      }
      secret = newSigningSecret();
      const sealed = sealSecret(secret, channel.id)!;
      data = { secretKeyId: sealed.keyId, secretSealed: sealed.sealed };
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
        details: { events: updated.events, huntIds: updated.huntIds, status: updated.status },
      },
    });
    return NextResponse.json({ channel: channelView(updated), ...(secret ? { secret } : {}) });
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
        details: { host: new URL(channel.url).host },
      },
    });
    return NextResponse.json({ status: "deleted" });
  } catch (error) {
    console.error("Delete notification channel error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
