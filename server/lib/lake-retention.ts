import { createHash, randomUUID } from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import type { LakeStore } from "@/lib/lake-store";

/**
 * The telemetry lake's retention job (issue #77, ADR-0041 section 5). A tenant's retention is
 * `tenants.lake_retention_days`; a `date=` partition whose age in days (UTC, against `now`) has
 * reached it is deleted whole, and each deletion writes a `LakeDeletion` row: the tenant, the date,
 * how many files and bytes and a hash of the listing, then what really went, what did not, and
 * whether the prefix listed empty afterwards. "Provable" means that row; it does not reach the
 * storage provider's own backups or versioning (ADR-0041).
 *
 * The row is written BEFORE the deletion and completed after it, so that a deletion which half
 * happens (a later batch fails, the process dies, the database goes away) leaves a record of what
 * it set out to remove, and a row with no `completedAt` says it never finished. One partition's
 * failure is recorded and the run goes on to the next: it does not stop the other tenants'.
 *
 * A retention of 0 keeps nothing, today's partition included. Lowering a tenant's retention deletes
 * at the next run; raising it does not bring anything back.
 *
 * Not deleted, on purpose: a `tenant=` prefix whose tenant no longer exists in Postgres. Deleting
 * on a guess about which tenant ids are real is how a bad lookup becomes data loss, so they are
 * counted and left for a person.
 */

const DAY_MS = 24 * 60 * 60 * 1000;
const TENANT_DIR = /^tenant=([A-Za-z0-9_-]+)\//;
const DATE_DIR = /^tenant=[A-Za-z0-9_-]+\/date=(\d{4}-\d{2}-\d{2})\//;

/** Whole days from the UTC date `YYYY-MM-DD` to the UTC day of `now`; negative for a date in the future. */
export function ageInDays(date: string, now: Date): number {
  const day = Date.parse(`${date}T00:00:00.000Z`);
  if (Number.isNaN(day)) return Number.NaN;
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return Math.round((today - day) / DAY_MS);
}

/** A partition is deleted once it is `retentionDays` old; an unparseable date is never deleted. */
export function isExpired(date: string, retentionDays: number, now: Date): boolean {
  const age = ageInDays(date, now);
  return !Number.isNaN(age) && age >= retentionDays;
}

export function manifestHash(files: { key: string; size: number }[]): string {
  const lines = files
    .map((f) => `${f.key}:${f.size}`)
    .sort()
    .join("\n");
  return createHash("sha256").update(lines).digest("hex");
}

export type RetentionResult = {
  runId: string;
  partitionsDeleted: number;
  filesDeleted: number;
  bytesDeleted: number;
  /** Partitions whose prefix did not list empty after the deletion (or could not be listed): the audit row says so and the job answers an error. */
  notEmpty: number;
  /** Partitions whose deletion hit an error or could not be recorded; the others in the run were still done. */
  failedPartitions: number;
  /** The first few error messages, for the log and the response. */
  errors: string[];
  /** `tenant=` prefixes with no tenant in Postgres, left untouched. */
  orphanTenantPrefixes: number;
};

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));
const MAX_ERRORS = 5;

export async function pruneLake(
  prisma: Pick<PrismaClient, "tenant" | "lakeDeletion">,
  store: LakeStore,
  now: Date = new Date()
): Promise<RetentionResult> {
  const runId = randomUUID();
  const all = await store.list("");
  const result: RetentionResult = {
    runId,
    partitionsDeleted: 0,
    filesDeleted: 0,
    bytesDeleted: 0,
    notEmpty: 0,
    failedPartitions: 0,
    errors: [],
    orphanTenantPrefixes: 0,
  };
  // A partition counts once however many things went wrong with it.
  const failed = new Set<string>();
  const fail = (where: string, what: string, e: unknown) => {
    failed.add(where);
    result.failedPartitions = failed.size;
    if (result.errors.length < MAX_ERRORS) result.errors.push(`${where}: ${what}: ${message(e)}`);
    console.error(`Lake retention: ${where}: ${what}:`, e);
  };

  const byTenant = new Map<string, Map<string, { key: string; size: number }[]>>();
  for (const file of all) {
    const t = TENANT_DIR.exec(file.key);
    const d = DATE_DIR.exec(file.key);
    if (!t || !d) continue; // not a lake partition: not ours to delete
    const dates = byTenant.get(t[1]) ?? new Map();
    const list = dates.get(d[1]) ?? [];
    list.push(file);
    dates.set(d[1], list);
    byTenant.set(t[1], dates);
  }

  const tenants = await prisma.tenant.findMany({
    where: { id: { in: Array.from(byTenant.keys()) } },
    select: { id: true, lakeRetentionDays: true },
  });
  const retention = new Map(tenants.map((t) => [t.id, t.lakeRetentionDays]));

  for (const [tenantId, dates] of Array.from(byTenant)) {
    const days = retention.get(tenantId);
    if (days === undefined) {
      result.orphanTenantPrefixes += 1;
      continue;
    }
    for (const [date, files] of Array.from(dates)) {
      if (!isExpired(date, days, now)) continue;
      const where = `tenant=${tenantId}/date=${date}`;
      const bytes = files.reduce((n, f) => n + f.size, 0);

      // Intent first. If this cannot be written nothing has been deleted, and the partition waits for the next run.
      let rowId: string;
      try {
        const row = await prisma.lakeDeletion.create({
          data: { tenantId, date, objectCount: files.length, bytes: BigInt(bytes), manifestSha256: manifestHash(files), runId, deletedAt: now },
        });
        rowId = row.id;
      } catch (e) {
        fail(where, "not deleted, the audit row could not be written", e);
        continue;
      }

      let deletedByStore: number | null = null;
      let firstError: string | null = null;
      let failedByStore = 0;
      try {
        const res = await store.delete(files.map((f) => f.key));
        deletedByStore = res.deleted.length;
        failedByStore = res.failed.length;
        if (res.failed.length > 0) firstError = `${res.failed[0].key}: ${res.failed[0].error}`;
      } catch (e) {
        firstError = message(e);
      }

      // What is really left decides, not what the store said: a delete that threw may have removed some.
      let left: number | null = null;
      try {
        left = (await store.list(`${where}/`)).length;
      } catch (e) {
        firstError ??= `could not list ${where}/ after the deletion: ${message(e)}`;
      }
      const deletedCount = left === null ? deletedByStore : files.length - left;
      const verifiedEmpty = left === 0;
      const failedCount = left ?? (failedByStore > 0 ? failedByStore : null);

      try {
        await prisma.lakeDeletion.update({
          where: { id: rowId },
          data: { completedAt: new Date(), deletedCount, failedCount, error: firstError, verifiedEmpty },
        });
      } catch (e) {
        fail(where, "deleted, but the audit row could not be completed", e);
      }

      if (deletedCount !== null && deletedCount > 0) {
        result.partitionsDeleted += 1;
        result.filesDeleted += deletedCount;
        result.bytesDeleted += bytes;
      }
      if (!verifiedEmpty) {
        result.notEmpty += 1;
        if (firstError !== null) fail(where, "not fully deleted", firstError);
      }
    }
  }
  return result;
}
