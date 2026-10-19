import { randomUUID } from "node:crypto";
import { Prisma, type PrismaClient } from "@prisma/client";
import { guardOptionsFromEnv } from "./guard";
import { nextDelayMs, PAUSE_AFTER_FAILED_ROWS } from "./backoff";
import { openSecret, type Env } from "./secret";
import { sendWebhook, type SendResult } from "./send";
import { signBody } from "./sign";

/**
 * The notification outbox (ADR-0036 point 3, #863). Producing an event writes a row;
 * `deliverDue` (the cron) claims due rows under a lease and sends them. Nothing here is on
 * the request path of a beacon or a hunt run.
 */

export const EVENTS = ["host.degraded", "host.silent", "host.recovered", "hunt.new_matches"] as const;
export type NotifyEvent = (typeof EVENTS)[number];

/** The cron's period: a tenant cooldown below it would mean nothing. */
export const CRON_PERIOD_SECONDS = 60;
export const LEASE_MS = 2 * 60_000;
export const TENANT_PER_MINUTE = 60;
export const CHANNELS_PER_TENANT = 5;

type Db = Pick<PrismaClient, "notificationChannel" | "notification" | "$transaction">;

export interface EnqueueInput {
  tenantId: string;
  event: NotifyEvent;
  /** The agent id or the hunt id. */
  subject: string;
  /** Subject block and the few fields of the state change: no detection contents (point 5). */
  data: Record<string, unknown>;
  occurredAt?: Date;
}

/**
 * Writes one row per subscribed channel, unless the same `(channel, event, subject)` is
 * already waiting or was delivered within the channel's cooldown (`host.recovered` always
 * goes). Returns how many rows were written.
 */
export async function enqueue(db: Db, input: EnqueueInput, now = new Date()): Promise<number> {
  const channels = await db.notificationChannel.findMany({
    where: {
      tenantId: input.tenantId,
      kind: "webhook",
      status: { in: ["active", "paused"] }, // a paused channel keeps queuing
      events: { has: input.event },
      ...(input.event === "hunt.new_matches" ? { huntIds: { has: input.subject } } : {}),
    },
  });

  let written = 0;
  for (const channel of channels) {
    if (input.event !== "host.recovered") {
      const cooldownMs = Math.max(channel.cooldownSeconds, CRON_PERIOD_SECONDS) * 1000;
      const blocking = await db.notification.findFirst({
        where: {
          channelId: channel.id,
          event: input.event,
          subject: input.subject,
          failedAt: null,
          OR: [{ deliveredAt: null }, { deliveredAt: { gt: new Date(now.getTime() - cooldownMs) } }],
        },
        select: { id: true },
      });
      if (blocking) continue;
    }

    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await db.$transaction(async (tx) => {
          const last = await tx.notification.aggregate({
            where: { channelId: channel.id, subject: input.subject },
            _max: { seq: true },
          });
          const id = randomUUID();
          const seq = (last._max.seq ?? 0) + 1;
          await tx.notification.create({
            data: {
              id,
              tenantId: input.tenantId,
              channelId: channel.id,
              event: input.event,
              subject: input.subject,
              seq,
              nextAttemptAt: now,
              payload: {
                id,
                event: input.event,
                tenant: input.tenantId,
                occurred_at: (input.occurredAt ?? now).toISOString(),
                seq,
                ...input.data,
              } as Prisma.InputJsonValue,
            },
          });
        });
        written++;
        break;
      } catch (e) {
        // Two producers took the same seq: the unique index refused one, retry with the next.
        if (!(e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002")) throw e;
      }
    }
  }
  return written;
}

interface Claimed {
  id: string;
  tenantId: string;
  channelId: string;
  attempts: number;
  payload: unknown;
}

/**
 * Claims due rows under a lease. A row waits behind an earlier undelivered row of the same
 * channel and subject (so `host.recovered` never overtakes a `host.degraded` that is backing
 * off), and rows of a paused or disabled channel are not claimed.
 */
export async function claimDue(
  db: Pick<PrismaClient, "$queryRaw">,
  now: Date,
  limit = 50
): Promise<Claimed[]> {
  const until = new Date(now.getTime() + LEASE_MS);
  return db.$queryRaw<Claimed[]>(Prisma.sql`
    UPDATE notifications n
       SET locked_until = ${until}
     WHERE n.id IN (
       SELECT q.id
         FROM notifications q
         JOIN notification_channels c ON c.id = q.channel_id
        WHERE q.delivered_at IS NULL
          AND q.failed_at IS NULL
          AND q.next_attempt_at <= ${now}
          AND (q.locked_until IS NULL OR q.locked_until < ${now})
          AND c.status = 'active'
          AND NOT EXISTS (
            SELECT 1 FROM notifications e
             WHERE e.channel_id = q.channel_id
               AND e.subject = q.subject
               AND e.seq < q.seq
               AND e.delivered_at IS NULL
               AND e.failed_at IS NULL)
        ORDER BY q.next_attempt_at
        LIMIT ${limit}
          FOR UPDATE OF q SKIP LOCKED)
    RETURNING n.id, n.tenant_id AS "tenantId", n.channel_id AS "channelId",
              n.attempts, n.payload`);
}

export type Sender = (url: string, body: string, headers: Record<string, string>) => Promise<SendResult>;

export interface DeliverDeps {
  send?: Sender;
  env?: Env;
}

/** Sends one claimed row and records the outcome. Never stores the response body. */
export async function deliverOne(
  db: PrismaClient,
  row: Claimed,
  now: Date,
  deps: DeliverDeps = {}
): Promise<"delivered" | "retry" | "failed" | "deferred"> {
  const env = deps.env ?? process.env;
  const send: Sender = deps.send ?? ((u, b, h) => sendWebhook(u, b, h, guardOptionsFromEnv(env)));

  const sentLastMinute = await db.notification.count({
    where: { tenantId: row.tenantId, lastAttemptAt: { gt: new Date(now.getTime() - 60_000) } },
  });
  if (sentLastMinute >= TENANT_PER_MINUTE) {
    // Over the tenant's rate: the row waits, it is not dropped.
    await db.notification.update({ where: { id: row.id }, data: { lockedUntil: null, nextAttemptAt: new Date(now.getTime() + 60_000) } });
    return "deferred";
  }

  const channel = await db.notificationChannel.findUnique({ where: { id: row.channelId } });
  let result: SendResult;
  if (!channel || channel.status !== "active") {
    await db.notification.update({ where: { id: row.id }, data: { lockedUntil: null } });
    return "deferred";
  }
  const secret = openSecret({ keyId: channel.secretKeyId, sealed: channel.secretSealed }, channel.id, env);
  if (secret === null) {
    result = { ok: false, errorClass: "blocked" }; // key missing or ciphertext not authentic
  } else {
    const body = JSON.stringify(row.payload);
    result = await send(channel.url, body, {
      "X-Synthaea-Signature": signBody(secret, body, Math.floor(now.getTime() / 1000)),
      "User-Agent": "synthaea-notify/1",
    });
  }

  const attempts = row.attempts + 1;
  const lastError = result.ok ? null : (result.errorClass ?? "connect");
  if (result.ok) {
    await db.$transaction([
      db.notification.update({
        where: { id: row.id },
        data: { attempts, deliveredAt: now, lastAttemptAt: now, lastStatus: result.statusCode ?? null, lastError: null, lockedUntil: null },
      }),
      db.notificationChannel.update({
        where: { id: channel.id },
        data: { lastStatusCode: result.statusCode ?? null, lastError: null, lastDeliveredAt: now },
      }),
    ]);
    return "delivered";
  }

  const delay = nextDelayMs(attempts);
  await db.notification.update({
    where: { id: row.id },
    data: {
      attempts,
      lastAttemptAt: now,
      lastStatus: result.statusCode ?? null,
      lastError,
      lockedUntil: null,
      ...(delay === null ? { failedAt: now } : { nextAttemptAt: new Date(now.getTime() + delay) }),
    },
  });
  await db.notificationChannel.update({
    where: { id: channel.id },
    data: { lastStatusCode: result.statusCode ?? null, lastError },
  });
  if (delay !== null) return "retry";

  // Five failed rows since the last delivery pause the channel; its rows stay queued.
  const failedSince = await db.notification.count({
    where: {
      channelId: channel.id,
      failedAt: { not: null, ...(channel.lastDeliveredAt ? { gt: channel.lastDeliveredAt } : {}) },
    },
  });
  if (failedSince >= PAUSE_AFTER_FAILED_ROWS) {
    await db.notificationChannel.update({ where: { id: channel.id }, data: { status: "paused" } });
  }
  return "failed";
}

/** One cron tick: claim and deliver what is due. */
export async function deliverDue(db: PrismaClient, now = new Date(), deps: DeliverDeps = {}) {
  const claimed = await claimDue(db, now);
  const tally = { claimed: claimed.length, delivered: 0, retry: 0, failed: 0, deferred: 0 };
  for (const row of claimed) {
    tally[await deliverOne(db, row, now, deps)]++;
  }
  return tally;
}
