import { createHash } from "node:crypto";
import { parquetWriteBuffer } from "hyparquet-writer";
import type { PrismaClient } from "@prisma/client";
import { eventTime } from "@/lib/event-time";
import type { LakeStore } from "@/lib/lake-store";

/**
 * The telemetry lake's write path (issue #77, ADR-0041, section 3): ingest queues each accepted
 * batch in Postgres (`LakeBatch`), and `drainLakeQueue` turns the queue into Parquet files laid
 * out `tenant=<id>/date=<YYYY-MM-DD>/type=<event_type>/<flush>.parquet`, one file per
 * (tenant, day, type) per drain.
 *
 * At-least-once: the files are written before the queue rows are deleted, in one transaction.
 * A crash between the two leaves the rows, and the retry writes them again. The file name is a
 * hash of the batches it holds, so a retry over the same batches rewrites the same files; a retry
 * over a different set (a slower request's older batch arriving in between) can leave the events
 * of that flush twice. Nothing in this slice removes such a duplicate.
 */

/** How many queued batches one drain takes (an agent batch is at most 1000 events, usually 100). */
export const DEFAULT_MAX_BATCHES = 200;

/** Bounds a typed column so an attacker-chosen path or name cannot bloat a file; the whole event stays in `event`. */
const MAX_COLUMN_LENGTH = 1024;

/** The `type=` path segment. An event's type is agent-supplied text and must not shape a path. */
const TYPE_SEGMENT = /^[a-z][a-z0-9_]{0,63}$/;

const SHA256 = /^[0-9a-f]{64}$/;

/** An event whose type is not a safe path segment lands here; its real type stays in the event. */
export const OTHER_TYPE = "other";

export function typeSegment(type: unknown): string {
  return typeof type === "string" && TYPE_SEGMENT.test(type) ? type : OTHER_TYPE;
}

/** The UTC day, as the `date=` segment. */
export function dayOf(at: Date): string {
  return at.toISOString().slice(0, 10);
}

export function lakeKey(tenantId: string, day: string, type: string, flushId: string): string {
  return `tenant=${tenantId}/date=${day}/type=${type}/${flushId}.parquet`;
}

function column(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value.slice(0, MAX_COLUMN_LENGTH) : null;
}

/** One event as the file holds it: a few typed columns, and the whole event. */
export type LakeRow = {
  agentId: string;
  at: Date;
  comm: string | null;
  path: string | null;
  imagePath: string | null;
  daddr: string | null;
  query: string | null;
  sha256: string | null;
  event: string;
};

export function lakeRow(agentId: string, event: Record<string, unknown>, receivedAt: Date): LakeRow {
  const meta = event.meta;
  const comm = typeof meta === "object" && meta !== null ? (meta as Record<string, unknown>).comm : undefined;
  const sha = typeof event.sha256 === "string" ? event.sha256.toLowerCase() : "";
  return {
    agentId,
    at: eventTime(event, receivedAt),
    comm: column(comm),
    path: column(event.path),
    imagePath: column(event.image_path),
    daddr: column(event.daddr),
    query: column(event.query),
    sha256: SHA256.test(sha) ? sha : null,
    event: JSON.stringify(event),
  };
}

export function encodeParquet(rows: LakeRow[]): Uint8Array {
  const data = (pick: (r: LakeRow) => string | Date | null) => rows.map(pick);
  return new Uint8Array(
    parquetWriteBuffer({
      columnData: [
        { name: "agent_id", data: data((r) => r.agentId), type: "STRING" },
        { name: "ts", data: data((r) => r.at), type: "TIMESTAMP" },
        { name: "comm", data: data((r) => r.comm), type: "STRING" },
        { name: "path", data: data((r) => r.path), type: "STRING" },
        { name: "image_path", data: data((r) => r.imagePath), type: "STRING" },
        { name: "daddr", data: data((r) => r.daddr), type: "STRING" },
        { name: "query", data: data((r) => r.query), type: "STRING" },
        { name: "sha256", data: data((r) => r.sha256), type: "STRING" },
        { name: "event", data: data((r) => r.event), type: "STRING" },
      ],
    })
  );
}

/**
 * Queues one accepted ingest batch. Throws when the insert fails: the caller answers 5xx and the
 * agent retries the segment, so a queue failure delays the lake and loses nothing.
 */
export async function enqueueLakeBatch(
  db: Pick<PrismaClient, "lakeBatch">,
  batch: { tenantId: string; agentId: string; events: unknown[]; receivedAt: Date }
): Promise<void> {
  if (batch.events.length === 0) return;
  await db.lakeBatch.create({
    data: {
      tenantId: batch.tenantId,
      agentId: batch.agentId,
      receivedAt: batch.receivedAt,
      events: batch.events as object[],
      eventCount: batch.events.length,
    },
  });
}

export type DrainResult = {
  batches: number;
  events: number;
  files: number;
  /** Events dropped because their tenant keeps nothing (`lakeRetentionDays` = 0). */
  droppedNoRetention: number;
  /** Queued events that were not objects with a string `type`. */
  skippedMalformed: number;
  /** Batches still queued after this drain. */
  remaining: number;
};

export async function drainLakeQueue(
  prisma: PrismaClient,
  store: Pick<LakeStore, "put">,
  opts: { maxBatches?: number } = {}
): Promise<DrainResult> {
  const max = opts.maxBatches ?? DEFAULT_MAX_BATCHES;
  return prisma.$transaction(
    async (tx) => {
      // SKIP LOCKED: two drains at once take different rows instead of waiting on, or repeating, each other.
      const picked = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM lake_batches ORDER BY received_at, id LIMIT ${max} FOR UPDATE SKIP LOCKED`;
      const empty: DrainResult = { batches: 0, events: 0, files: 0, droppedNoRetention: 0, skippedMalformed: 0, remaining: 0 };
      if (picked.length === 0) return empty;

      const ids = picked.map((r) => r.id);
      const batches = await tx.lakeBatch.findMany({ where: { id: { in: ids } }, orderBy: [{ receivedAt: "asc" }, { id: "asc" }] });
      const tenants = await tx.tenant.findMany({
        where: { id: { in: Array.from(new Set(batches.map((b) => b.tenantId))) } },
        select: { id: true, lakeRetentionDays: true },
      });
      const keepsNothing = new Set(tenants.filter((t) => t.lakeRetentionDays === 0).map((t) => t.id));
      // A tenant that no longer exists cascades its batches away; one that raced the delete has no row here.
      const known = new Set(tenants.map((t) => t.id));

      const groups = new Map<string, { tenantId: string; day: string; type: string; rows: LakeRow[]; batchIds: Set<string> }>();
      let events = 0;
      let droppedNoRetention = 0;
      let skippedMalformed = 0;
      for (const batch of batches) {
        if (!known.has(batch.tenantId)) continue;
        const list = Array.isArray(batch.events) ? batch.events : [];
        for (const raw of list) {
          if (typeof raw !== "object" || raw === null || Array.isArray(raw) || typeof (raw as { type?: unknown }).type !== "string") {
            skippedMalformed += 1;
            continue;
          }
          if (keepsNothing.has(batch.tenantId)) {
            droppedNoRetention += 1;
            continue;
          }
          const event = raw as Record<string, unknown>;
          const row = lakeRow(batch.agentId, event, batch.receivedAt);
          const type = typeSegment(event.type);
          const day = dayOf(row.at);
          const gk = `${batch.tenantId}\u0000${day}\u0000${type}`;
          let group = groups.get(gk);
          if (!group) {
            group = { tenantId: batch.tenantId, day, type, rows: [], batchIds: new Set() };
            groups.set(gk, group);
          }
          group.rows.push(row);
          group.batchIds.add(batch.id);
          events += 1;
        }
      }

      for (const g of Array.from(groups.values())) {
        const flushId = createHash("sha256").update(Array.from(g.batchIds).sort().join(",")).digest("hex").slice(0, 32);
        await store.put(lakeKey(g.tenantId, g.day, g.type, flushId), encodeParquet(g.rows));
      }

      await tx.lakeBatch.deleteMany({ where: { id: { in: ids } } });
      const remaining = await tx.lakeBatch.count();
      return { batches: ids.length, events, files: groups.size, droppedNoRetention, skippedMalformed, remaining };
    },
    // The transaction holds the row locks while the files are written.
    { timeout: 120_000, maxWait: 10_000 }
  );
}
