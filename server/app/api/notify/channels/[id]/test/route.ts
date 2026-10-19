import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireTenantAdmin } from "@/lib/admin-auth";
import { guardOptionsFromEnv } from "@/lib/notify/guard";
import { openSecret } from "@/lib/notify/secret";
import { sendWebhook } from "@/lib/notify/send";
import { signBody } from "@/lib/notify/sign";
import { randomUUID } from "node:crypto";

/**
 * POST /api/notify/channels/{id}/test — tenant `owner`/`admin` only. Sends one signed
 * `test` event, outside the outbox, and answers with a status code and a coarse error class
 * (`blocked`, `dns`, `connect`, `tls`, `timeout`, `http_status`): never the finer cause, so it
 * is not a port-scan oracle.
 */
export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const authed = await requireTenantAdmin(req);
    if ("response" in authed) return authed.response;
    const { tenantId, userId } = authed;

    const channel = await prisma.notificationChannel.findFirst({ where: { id: params.id, tenantId } });
    if (!channel) return NextResponse.json({ error: "Channel not found" }, { status: 404 });

    const secret = openSecret({ keyId: channel.secretKeyId, sealed: channel.secretSealed }, channel.id);
    if (secret === null) {
      return NextResponse.json({ ok: false, errorClass: "blocked" });
    }
    const now = new Date();
    const body = JSON.stringify({
      id: randomUUID(),
      event: "test",
      tenant: tenantId,
      occurred_at: now.toISOString(),
      seq: 0,
    });
    const result = await sendWebhook(
      channel.url,
      body,
      {
        "X-Synthaea-Signature": signBody(secret, body, Math.floor(now.getTime() / 1000)),
        "User-Agent": "synthaea-notify/1",
      },
      guardOptionsFromEnv()
    );

    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "notify.channel.test",
        resource: `notification_channels/${channel.id}`,
        details: { ok: result.ok, statusCode: result.statusCode ?? null, errorClass: result.errorClass ?? null },
      },
    });
    return NextResponse.json(result);
  } catch (error) {
    console.error("Test notification channel error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
