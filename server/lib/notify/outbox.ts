import { randomUUID } from "node:crypto";
import { Prisma, type NotificationChannel, type PrismaClient } from "@prisma/client";
import { guardOptionsFromEnv } from "./guard";
import {
  MAX_DELAY_MS,
  nextDelayMs,
  PAUSE_AFTER_FAILED_ROWS,
  RETENTION_DELIVERED_DAYS,
  RETENTION_FAILED_DAYS,
} from "./backoff";
import { openSecret, openUrl, type Env } from "./secret";
import { sendWebhook, type SendResult } from "./send";
import { signBody } from "./sign";

/**
 * The notification outbox (ADR-0036 point 3, #863). Producing an event writes a row;
 * `deliverDue` (the cron) claims due rows under a lease and sends them. Nothing here is on
 * the request path of a beacon or a hunt run.
 */

export const EVENTS = ["host.degraded", "host.silent", "host.recovered", "hunt.new_matches"] as const;
export type NotifyEvent = (typeof EVENTS)[number];

/** The cron's period: a channel cooldown below it would mean nothing. */
export const CRON_PERIOD_SECONDS = 60;
/** A row is leased for longer than a tick can last, so a slow tick never sees its rows re-claimed. */
export const LEASE_MS = 5 * 60_000;
/** After this long a tick stops starting sends (an in-flight send ends within its own 10 s deadline). */
export const TICK_BUDGET_MS = 45_000;
/** Rows one tenant may have claimed in one tick: tenants are served round-robin. */
export const PER_TENANT_PER_TICK = 10;
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
 * Writes the row for one channel, unless the same `(channel, event, subject)` is already waiting
 * or was delivered within the channel's cooldown (`host.recovered` always goes). Returns the
 * number of rows written (0 or 1): the caller advances the channel's state only when it is 1.
 */
export async function enqueueForChannel(
  db: Db,
  channel: Pick<NotificationChannel, "id" | "cooldownSeconds">,
  input: EnqueueInput,
  now = new Date()
): Promise<number> {
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
    if (blocking) return 0;
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
      return 1;
    } catch (e) {
      // Two producers took the same seq: the unique index refused one, retry with the next.
      if (!(e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002")) throw e;
    }
  }
  return 0;
}

/**
 * For every channel of the tenant that is subscribed to the event (and, for a hunt event, lists
 * the hunt), `enqueueForChannel`. A paused channel keeps queuing. Returns how many rows were written.
 */
export async function enqueue(db: Db, input: EnqueueInput, now = new Date()): Promise<number> {
  const channels = await db.notificationChannel.findMany({
    where: {
      tenantId: input.tenantId,
      kind: "webhook",
      status: { in: ["active", "paused"] },
      events: { has: input.event },
      ...(input.event === "hunt.new_matches" ? { huntIds: { has: input.subject } } : {}),
    },
  });
  let written = 0;
  for (const channel of channels) written += await enqueueForChannel(db, channel, input, now);
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
 * Claims due rows under a lease, tenants round-robin and at most `perTenant` rows each (so one
 * tenant's slow receivers do not delay the others). A row waits behind an earlier *pending* row
 * of the same channel and subject (so `host.recovered` never overtakes a `host.degraded` that
 * is backing off); a row that has reached `failed` no longer blocks. Rows of a paused or
 * disabled channel are not claimed.
 *
 * `FOR UPDATE` cannot sit in the same query as a window function, so the ranking is a first
 * pass and the lock is taken in the second, which checks the conditions again.
 */
export async function claimDue(
  db: Pick<PrismaClient, "$queryRaw">,
  now: Date,
  opts: { perTenant?: number; limit?: number } = {}
): Promise<Claimed[]> {
  const perTenant = opts.perTenant ?? PER_TENANT_PER_TICK;
  const limit = opts.limit ?? 200;
  const until = new Date(now.getTime() + LEASE_MS);
  return db.$queryRaw<Claimed[]>(Prisma.sql`
    UPDATE notifications n
       SET locked_until = ${until}
      FROM (
        SELECT r.id, r.rn, r.next_attempt_at
          FROM (
            SELECT q.id, q.next_attempt_at,
                   row_number() OVER (PARTITION BY q.tenant_id ORDER BY q.next_attempt_at, q.created_at) AS rn
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
          ) r
         WHERE r.rn <= ${perTenant}
         ORDER BY r.rn, r.next_attempt_at
         LIMIT ${limit}
      ) pick
     WHERE n.id = pick.id
       AND n.delivered_at IS NULL
       AND n.failed_at IS NULL
       AND (n.locked_until IS NULL OR n.locked_until < ${now})
       AND n.id IN (SELECT id FROM notifications WHERE id = pick.id FOR UPDATE SKIP LOCKED)
    RETURNING n.id, n.tenant_id AS "tenantId", n.channel_id AS "channelId", n.attempts, n.payload`);
}

export type Sender = (url: string, body: string, headers: Record<string, string>) => Promise<SendResult>;

export interface DeliverDeps {
  send?: Sender;
  env?: Env;
}

export type Outcome = "delivered" | "retry" | "failed" | "deferred" | "paused";

/** A 2xx is a delivery; these statuses and any network error are retried; any other answer is final. */
function isRetryable(r: SendResult): boolean {
  const s = r.statusCode;
  if (s === undefined) return true; // network error, timeout, TLS, blocked: the schedule decides
  return s === 408 || s === 425 || s === 429 || s >= 500;
}

/** Sends one claimed row and records the outcome. Never stores the response body. */
export async function deliverOne(
  db: PrismaClient,
  row: Claimed,
  now: Date,
  deps: DeliverDeps = {}
): Promise<Outcome> {
  const env = deps.env ?? process.env;

  const sentLastMinute = await db.notification.count({
    where: { tenantId: row.tenantId, lastAttemptAt: { gt: new Date(now.getTime() - 60_000) } },
  });
  if (sentLastMinute >= TENANT_PER_MINUTE) {
    // Over the tenant's rate: the row waits, it is not dropped.
    await db.notification.update({ where: { id: row.id }, data: { lockedUntil: null, nextAttemptAt: new Date(now.getTime() + 60_000) } });
    return "deferred";
  }

  const channel = await db.notificationChannel.findUnique({ where: { id: row.channelId } });
  if (!channel || channel.status !== "active") {
    await db.notification.update({ where: { id: row.id }, data: { lockedUntil: null } });
    return "deferred";
  }

  let result: SendResult;
  const url = openUrl({ keyId: channel.urlKeyId, sealed: channel.urlSealed }, channel.id, env);
  const secret = openSecret({ keyId: channel.secretKeyId, sealed: channel.secretSealed }, channel.id, env);
  if (url === null || secret === null) {
    result = { ok: false, errorClass: "blocked" }; // key missing or ciphertext not authentic
  } else {
    // Rotation overlap: while the previous secret is still valid, both sign (new first).
    const secrets = [secret];
    if (channel.prevSecretSealed && channel.prevSecretKeyId && channel.prevSecretUntil && channel.prevSecretUntil > now) {
      const prev = openSecret({ keyId: channel.prevSecretKeyId, sealed: channel.prevSecretSealed }, channel.id, env);
      if (prev !== null) secrets.push(prev);
    }
    const body = JSON.stringify(row.payload);
    const headers = {
      "X-Synthaea-Signature": signBody(secrets, body, Math.floor(now.getTime() / 1000)),
      "User-Agent": "synthaea-notify/1",
    };
    const send: Sender =
      deps.send ?? ((u, b, h) => sendWebhook(u, b, h, { ...guardOptionsFromEnv(env), tenantId: channel.tenantId }));
    result = await send(url, body, headers);
  }

  const attempts = row.attempts + 1;
  const lastError = result.ok ? null : (result.errorClass ?? "connect");
  const base = { attempts, lastAttemptAt: now, lastStatus: result.statusCode ?? null, lockedUntil: null };

  if (result.ok) {
    await db.$transaction([
      db.notification.update({ where: { id: row.id }, data: { ...base, deliveredAt: now, lastError: null } }),
      db.notificationChannel.update({
        where: { id: channel.id },
        data: { lastStatusCode: result.statusCode ?? null, lastError: null, lastDeliveredAt: now },
      }),
    ]);
    return "delivered";
  }

  await db.notificationChannel.update({
    where: { id: channel.id },
    data: { lastStatusCode: result.statusCode ?? null, lastError },
  });

  // 410: the receiver says it is gone. The channel pauses at once; the row is kept and goes out,
  // oldest first, when an admin re-enables it.
  if (result.statusCode === 410) {
    await db.notification.update({ where: { id: row.id }, data: { ...base, lastError, nextAttemptAt: now } });
    await db.notificationChannel.update({ where: { id: channel.id }, data: { status: "paused" } });
    return "paused";
  }

  let delay: number | null = null;
  if (isRetryable(result)) {
    delay = nextDelayMs(attempts);
    if (delay !== null && result.retryAfterSeconds !== undefined && (result.statusCode === 429 || result.statusCode === 503)) {
      // Honoured, never shorter than the schedule, capped at the largest step.
      delay = Math.min(Math.max(delay, result.retryAfterSeconds * 1000), MAX_DELAY_MS);
    }
  }
  await db.notification.update({
    where: { id: row.id },
    data: {
      ...base,
      lastError,
      ...(delay === null ? { failedAt: now } : { nextAttemptAt: new Date(now.getTime() + delay) }),
    },
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

/**
 * Housekeeping, once per tick: delivered rows go after 30 days, failed rows after 90, and a
 * rotation's previous secret is forgotten once its 24 hours are over.
 */
export async function purge(db: PrismaClient, now: Date) {
  const day = 86_400_000;
  const delivered = await db.notification.deleteMany({
    where: { deliveredAt: { lt: new Date(now.getTime() - RETENTION_DELIVERED_DAYS * day) } },
  });
  const failed = await db.notification.deleteMany({
    where: { failedAt: { lt: new Date(now.getTime() - RETENTION_FAILED_DAYS * day) } },
  });
  const rotations = await db.notificationChannel.updateMany({
    where: { prevSecretUntil: { lt: now } },
    data: { prevSecretKeyId: null, prevSecretSealed: null, prevSecretUntil: null },
  });
  return { deliveredDeleted: delivered.count, failedDeleted: failed.count, rotationsClosed: rotations.count };
}

/** One cron tick: claim and deliver what is due, within the tick's budget. */
export async function deliverDue(
  db: PrismaClient,
  now = new Date(),
  deps: DeliverDeps & { budgetMs?: number } = {}
) {
  const started = Date.now();
  const budget = deps.budgetMs ?? TICK_BUDGET_MS;
  const claimed = await claimDue(db, now);
  const tally = { claimed: claimed.length, delivered: 0, retry: 0, failed: 0, deferred: 0, paused: 0, released: 0 };
  for (let i = 0; i < claimed.length; i++) {
    if (Date.now() - started > budget) {
      // Out of time: stop claiming and give the rest back, so the next tick takes them.
      const rest = claimed.slice(i).map((r) => r.id);
      await db.notification.updateMany({ where: { id: { in: rest } }, data: { lockedUntil: null } });
      tally.released = rest.length;
      break;
    }
    tally[await deliverOne(db, claimed[i], now, deps)]++;
  }
  return tally;
}

/**
 * Puts the channel's `failed` rows back in the queue, except those a later row of the same
 * subject has superseded: a receiver applies an event only if its `seq` is above the last it
 * applied, so sending an old failed state again after a newer one is noise at best.
 */
export async function resendFailed(db: Pick<PrismaClient, "$executeRaw">, channelId: string, now: Date): Promise<number> {
  return db.$executeRaw(Prisma.sql`
    UPDATE notifications n
       SET failed_at = NULL, attempts = 0, next_attempt_at = ${now}, locked_until = NULL, last_error = NULL
     WHERE n.channel_id = ${channelId}
       AND n.failed_at IS NOT NULL
       AND NOT EXISTS (
         SELECT 1 FROM notifications l
          WHERE l.channel_id = n.channel_id AND l.subject = n.subject AND l.seq > n.seq)`);
}

/** Per channel of a tenant: failed rows that can be sent again, and those superseded by a later row. */
export async function failedCounts(
  db: Pick<PrismaClient, "$queryRaw">,
  tenantId: string
): Promise<Map<string, { resendable: number; superseded: number }>> {
  const rows = await db.$queryRaw<{ channelId: string; resendable: bigint; superseded: bigint }[]>(Prisma.sql`
    SELECT n.channel_id AS "channelId",
           count(*) FILTER (WHERE NOT EXISTS (
             SELECT 1 FROM notifications l
              WHERE l.channel_id = n.channel_id AND l.subject = n.subject AND l.seq > n.seq)) AS resendable,
           count(*) FILTER (WHERE EXISTS (
             SELECT 1 FROM notifications l
              WHERE l.channel_id = n.channel_id AND l.subject = n.subject AND l.seq > n.seq)) AS superseded
      FROM notifications n
     WHERE n.tenant_id = ${tenantId} AND n.failed_at IS NOT NULL
     GROUP BY n.channel_id`);
  return new Map(rows.map((r) => [r.channelId, { resendable: Number(r.resendable), superseded: Number(r.superseded) }]));
}

/** A deleted hunt drops out of the hunt lists that hold it (ADR-0036 point 2). */
export async function dropHuntFromChannels(
  db: Pick<PrismaClient, "$executeRaw">,
  tenantId: string,
  huntId: string
): Promise<void> {
  await db.$executeRaw(Prisma.sql`
    UPDATE notification_channels SET hunt_ids = array_remove(hunt_ids, ${huntId})
     WHERE tenant_id = ${tenantId} AND ${huntId} = ANY(hunt_ids)`);
}
