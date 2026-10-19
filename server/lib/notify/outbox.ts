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
import { currentKey, openSecret, openUrl, sealSecret, sealUrl, type Env } from "./secret";
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
  // The check and the insert run under one advisory lock per (channel, subject): two overlapping
  // evaluations cannot both pass the check and write two rows with different ids.
  return db.$transaction(async (tx) => {
    await tx.$executeRaw(Prisma.sql`SELECT pg_advisory_xact_lock(hashtext(${`notify:${channel.id}:${input.subject}`}))`);

    if (input.event !== "host.recovered") {
      const cooldownMs = Math.max(channel.cooldownSeconds, CRON_PERIOD_SECONDS) * 1000;
      const blocking = await tx.notification.findFirst({
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
    return 1;
  });
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
  leaseId: string;
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
  const leaseId = randomUUID();
  return db.$queryRaw<Claimed[]>(Prisma.sql`
    UPDATE notifications n
       SET locked_until = ${until}, lease_id = ${leaseId}
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
    RETURNING n.id, n.tenant_id AS "tenantId", n.channel_id AS "channelId", n.attempts, n.payload,
              n.lease_id AS "leaseId"`);
}

export type Sender = (url: string, body: string, headers: Record<string, string>) => Promise<SendResult>;

export interface DeliverDeps {
  send?: Sender;
  env?: Env;
}

export type Outcome = "delivered" | "retry" | "failed" | "deferred" | "paused" | "lost";

/** A 2xx is a delivery; these statuses and any network error are retried; any other answer is final. */
function isRetryable(r: SendResult): boolean {
  const s = r.statusCode;
  if (s === undefined) return true; // network error, timeout, TLS, blocked: the schedule decides
  return s === 408 || s === 425 || s === 429 || s >= 500;
}

/**
 * Sends one claimed row and records the outcome. Never stores the response body. Every write
 * to the row names the claim (`leaseId`): if the lease ran out and another tick took the row
 * over, this tick's write matches nothing and the outcome is "lost", not an overwrite.
 */
export async function deliverOne(
  db: PrismaClient,
  row: Claimed,
  now: Date,
  deps: DeliverDeps = {}
): Promise<Outcome> {
  const env = deps.env ?? process.env;
  const mine = { id: row.id, leaseId: row.leaseId };
  const write = async (data: Prisma.NotificationUncheckedUpdateManyInput) =>
    (await db.notification.updateMany({ where: mine, data })).count === 1;
  const release = (data: Prisma.NotificationUncheckedUpdateManyInput = {}) =>
    write({ lockedUntil: null, leaseId: null, ...data });

  const sentLastMinute = await db.notification.count({
    where: { tenantId: row.tenantId, lastAttemptAt: { gt: new Date(now.getTime() - 60_000) } },
  });
  if (sentLastMinute >= TENANT_PER_MINUTE) {
    // Over the tenant's rate: the row waits, it is not dropped.
    await release({ nextAttemptAt: new Date(now.getTime() + 60_000) });
    return "deferred";
  }

  const channel = await db.notificationChannel.findUnique({ where: { id: row.channelId } });
  if (!channel || channel.status !== "active") {
    await release();
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
    // Signed now, not at the tick's start: a row late in a slow batch must still pass a receiver's
    // freshness window.
    const headers = {
      "X-Synthaea-Signature": signBody(secrets, body, Math.floor(Date.now() / 1000)),
      "User-Agent": "synthaea-notify/1",
    };
    const send: Sender =
      deps.send ?? ((u, b, h) => sendWebhook(u, b, h, { ...guardOptionsFromEnv(env), tenantId: channel.tenantId }));
    result = await send(url, body, headers);
  }

  const attempts = row.attempts + 1;
  const lastError = result.ok ? null : (result.errorClass ?? "connect");
  const base = { attempts, lastAttemptAt: now, lastStatus: result.statusCode ?? null, lockedUntil: null, leaseId: null };

  if (result.ok) {
    if (!(await write({ ...base, deliveredAt: now, lastError: null }))) return "lost";
    await db.notificationChannel.update({
      where: { id: channel.id },
      data: { lastStatusCode: result.statusCode ?? null, lastError: null, lastDeliveredAt: now },
    });
    return "delivered";
  }

  // 410: the receiver says it is gone. The channel pauses at once; the row is kept and goes out,
  // oldest first, when an admin re-enables it.
  if (result.statusCode === 410) {
    if (!(await write({ ...base, lastError, nextAttemptAt: now }))) return "lost";
    await db.notificationChannel.update({
      where: { id: channel.id },
      data: { status: "paused", lastStatusCode: 410, lastError },
    });
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
  const wrote = await write({
    ...base,
    lastError,
    ...(delay === null ? { failedAt: now } : { nextAttemptAt: new Date(now.getTime() + delay) }),
  });
  if (!wrote) return "lost";
  await db.notificationChannel.update({
    where: { id: channel.id },
    data: { lastStatusCode: result.statusCode ?? null, lastError },
  });
  if (delay !== null) return "retry";

  // Five failed rows in a row pause the channel: counted from the last delivery, or from the
  // last re-enable if that is later (otherwise one new failure after a re-enable would pause it
  // again); its rows stay queued.
  const since = [channel.lastDeliveredAt, channel.pauseCountFrom]
    .filter((d): d is Date => d !== null)
    .sort((x, y) => y.getTime() - x.getTime())[0];
  const failedSince = await db.notification.count({
    where: { channelId: channel.id, failedAt: { not: null, ...(since ? { gt: since } : {}) } },
  });
  if (failedSince >= PAUSE_AFTER_FAILED_ROWS) {
    await db.notificationChannel.update({ where: { id: channel.id }, data: { status: "paused" } });
  }
  return "failed";
}

/**
 * Housekeeping, once per tick: delivered rows go after 30 days, failed rows after 90, a
 * rotation's previous secret is forgotten once its 24 hours are over, and the secrets and URLs
 * sealed under an older server key are sealed again under the current one (a few channels a
 * tick), so an old key can be retired.
 */
export async function purge(db: PrismaClient, now: Date, env: Env = process.env) {
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
  const rewrapped = await rewrapChannels(db, env);
  return { deliveredDeleted: delivered.count, failedDeleted: failed.count, rotationsClosed: rotations.count, rewrapped };
}

/** Seals again, under the current key, what an older key sealed. Returns how many channels changed. */
export async function rewrapChannels(db: PrismaClient, env: Env = process.env, limit = 20): Promise<number> {
  const key = currentKey(env);
  if (!key) return 0;
  const stale = await db.notificationChannel.findMany({
    where: {
      OR: [
        { secretKeyId: { not: key.id } },
        { urlKeyId: { not: key.id } },
        { prevSecretKeyId: { not: null, notIn: [key.id] } },
      ],
    },
    take: limit,
  });
  let changed = 0;
  for (const c of stale) {
    const secret = openSecret({ keyId: c.secretKeyId, sealed: c.secretSealed }, c.id, env);
    const url = openUrl({ keyId: c.urlKeyId, sealed: c.urlSealed }, c.id, env);
    if (secret === null || url === null) continue; // an old key that is gone: nothing to re-wrap with
    const s = sealSecret(secret, c.id, env);
    const u = sealUrl(url, c.id, env);
    if (!s || !u) continue;
    let prev: { prevSecretKeyId: string; prevSecretSealed: string } | undefined;
    if (c.prevSecretKeyId && c.prevSecretSealed) {
      const p = openSecret({ keyId: c.prevSecretKeyId, sealed: c.prevSecretSealed }, c.id, env);
      const ps = p === null ? null : sealSecret(p, c.id, env);
      if (ps) prev = { prevSecretKeyId: ps.keyId, prevSecretSealed: ps.sealed };
    }
    await db.notificationChannel.update({
      where: { id: c.id },
      data: { secretKeyId: s.keyId, secretSealed: s.sealed, urlKeyId: u.keyId, urlSealed: u.sealed, ...(prev ?? {}) },
    });
    changed++;
  }
  return changed;
}

/** How many tenants are served at once: a slow receiver stalls its own tenant, not the others. */
export const TENANT_CONCURRENCY = 8;

/**
 * One cron tick: claim and deliver what is due, within the tick's budget. Tenants run in
 * parallel, each tenant's rows in order; one row's error is logged and the lease released, it
 * does not end the tick.
 */
export async function deliverDue(
  db: PrismaClient,
  now = new Date(),
  deps: DeliverDeps & { budgetMs?: number } = {}
) {
  const started = Date.now();
  const budget = deps.budgetMs ?? TICK_BUDGET_MS;
  const claimed = await claimDue(db, now);
  const tally = { claimed: claimed.length, delivered: 0, retry: 0, failed: 0, deferred: 0, paused: 0, lost: 0, released: 0, errors: 0 };

  const byTenant = new Map<string, Claimed[]>();
  for (const r of claimed) byTenant.set(r.tenantId, [...(byTenant.get(r.tenantId) ?? []), r]);
  const queue = Array.from(byTenant.values());

  const runTenant = async (rows: Claimed[]) => {
    for (let i = 0; i < rows.length; i++) {
      if (Date.now() - started > budget) {
        // Out of time: stop sending and give the rest back, so the next tick takes them.
        for (const r of rows.slice(i)) {
          await db.notification.updateMany({ where: { id: r.id, leaseId: r.leaseId }, data: { lockedUntil: null, leaseId: null } });
          tally.released++;
        }
        return;
      }
      try {
        tally[await deliverOne(db, rows[i], now, deps)]++;
      } catch (error) {
        console.error("Notification delivery error:", rows[i].id, error);
        tally.errors++;
        await db.notification
          .updateMany({ where: { id: rows[i].id, leaseId: rows[i].leaseId }, data: { lockedUntil: null, leaseId: null } })
          .catch(() => undefined);
      }
    }
  };
  const worker = async () => {
    for (let rows = queue.shift(); rows; rows = queue.shift()) await runTenant(rows);
  };
  await Promise.all(Array.from({ length: Math.min(TENANT_CONCURRENCY, queue.length) }, worker));
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
