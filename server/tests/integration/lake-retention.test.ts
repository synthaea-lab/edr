import { mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { FsLakeStore } from "@/lib/lake-store";
import { drainLakeQueue, enqueueLakeBatch } from "@/lib/lake-writer";
import { manifestHash, pruneLake } from "@/lib/lake-retention";
import { GET as pruneRoute } from "@/app/api/cron/prune-lake/route";

const DAY = 86_400_000;
const NOW = new Date(Date.UTC(2026, 9, 29, 12, 0, 0));
const event = (at: Date, over: Record<string, unknown> = {}) => ({
  type: "exec",
  meta: { comm: "bash", timestamp_ns: at.getTime() * 1_000_000 },
  image_path: "/usr/bin/curl",
  ...over,
});

let dir: string;
let store: FsLakeStore;

beforeEach(async () => {
  await cleanDatabase();
  await prisma.lakeDeletion.deleteMany();
  dir = await mkdtemp(path.join(os.tmpdir(), "lake-ret-int-"));
  store = new FsLakeStore(dir);
  process.env.CRON_SECRET = "test_cron_secret";
});

afterEach(async () => {
  delete process.env.LAKE_DIR;
  await rm(dir, { recursive: true, force: true });
});

afterAll(async () => {
  await prisma.lakeDeletion.deleteMany();
  await cleanDatabase();
  await prisma.$disconnect();
});

/** Writes events dated `daysAgo` days before NOW through the real writer. */
async function write(tenantId: string, agentId: string, daysAgo: number, count = 2) {
  const at = new Date(NOW.getTime() - daysAgo * DAY);
  await enqueueLakeBatch(prisma, { tenantId, agentId, events: Array.from({ length: count }, (_, i) => event(at, { image_path: `/p/${daysAgo}/${i}` })), receivedAt: at });
  await drainLakeQueue(prisma, store);
}

describe("lake retention against Postgres", () => {
  it("deletes what the writer wrote once it is past the tenant's retention, and keeps the rest", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await prisma.tenant.update({ where: { id: tenant.id }, data: { lakeRetentionDays: 30 } });
    await write(tenant.id, agent.id, 100);
    await write(tenant.id, agent.id, 31);
    await write(tenant.id, agent.id, 29);
    await write(tenant.id, agent.id, 0);

    const before = await store.list(`tenant=${tenant.id}/`);
    expect(before).toHaveLength(4);
    const result = await pruneLake(prisma, store, NOW);
    expect(result).toMatchObject({ partitionsDeleted: 2, filesDeleted: 2, notEmpty: 0, orphanTenantPrefixes: 0 });

    const left = (await store.list(`tenant=${tenant.id}/`)).map((f) => f.key.split("/")[1]);
    expect(left.sort()).toEqual(["date=2026-09-30", "date=2026-10-29"]);

    const rows = await prisma.lakeDeletion.findMany({ orderBy: { date: "asc" } });
    expect(rows.map((r) => r.date)).toEqual(["2026-07-21", "2026-09-28"]);
    expect(rows.every((r) => r.tenantId === tenant.id && r.verifiedEmpty && r.objectCount === 1 && r.deletedCount === 1 && r.failedCount === 0 && r.error === null && r.completedAt !== null && r.runId === result.runId)).toBe(true);
    const gone = before.filter((f) => f.key.includes("date=2026-07-21"));
    expect(rows[0].manifestSha256).toBe(manifestHash(gone));
    expect(rows[0].bytes).toBe(BigInt(gone[0].size));
    expect(rows[0].deletedAt).toEqual(NOW);
  });

  it("a second run deletes nothing more and writes no second record", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await prisma.tenant.update({ where: { id: tenant.id }, data: { lakeRetentionDays: 1 } });
    await write(tenant.id, agent.id, 10);
    expect((await pruneLake(prisma, store, NOW)).partitionsDeleted).toBe(1);
    expect((await pruneLake(prisma, store, NOW)).partitionsDeleted).toBe(0);
    expect(await prisma.lakeDeletion.count()).toBe(1);
  });

  it("lowering a tenant's retention deletes at the next run, raising it brings nothing back", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await write(tenant.id, agent.id, 60);
    expect((await pruneLake(prisma, store, NOW)).partitionsDeleted).toBe(0); // 90 days by default
    await prisma.tenant.update({ where: { id: tenant.id }, data: { lakeRetentionDays: 30 } });
    expect((await pruneLake(prisma, store, NOW)).partitionsDeleted).toBe(1);
    await prisma.tenant.update({ where: { id: tenant.id }, data: { lakeRetentionDays: 365 } });
    expect(await store.list(`tenant=${tenant.id}/`)).toEqual([]);
  });

  it("leaves another tenant's old files alone", async () => {
    const [t1, t2] = [await createTestTenant(), await createTestTenant()];
    const [a1, a2] = [await createTestAgent(t1.id), await createTestAgent(t2.id)];
    await prisma.tenant.update({ where: { id: t1.id }, data: { lakeRetentionDays: 7 } });
    await write(t1.id, a1.id, 20);
    await write(t2.id, a2.id, 20);
    await pruneLake(prisma, store, NOW);
    expect(await store.list(`tenant=${t1.id}/`)).toEqual([]);
    expect(await store.list(`tenant=${t2.id}/`)).toHaveLength(1);
  });

  it("keeps the deletion record after the tenant is deleted, and leaves the orphan prefix for a person", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await prisma.tenant.update({ where: { id: tenant.id }, data: { lakeRetentionDays: 1 } });
    await write(tenant.id, agent.id, 10);
    await pruneLake(prisma, store, NOW);
    await prisma.agent.deleteMany({ where: { tenantId: tenant.id } });
    await prisma.tenant.delete({ where: { id: tenant.id } });
    expect(await prisma.lakeDeletion.count({ where: { tenantId: tenant.id } })).toBe(1);

    // A file for a tenant that is gone is reported, not deleted.
    await store.put(`tenant=${tenant.id}/date=2020-01-01/type=exec/orphan.parquet`, new Uint8Array(1));
    expect(await pruneLake(prisma, store, NOW)).toMatchObject({ orphanTenantPrefixes: 1, partitionsDeleted: 0 });
    expect(await store.list(`tenant=${tenant.id}/`)).toHaveLength(1);
  });

  it("keeps a record of a partition it could not delete, and still does the others", async () => {
    const [t1, t2] = [await createTestTenant(), await createTestTenant()];
    const [a1, a2] = [await createTestAgent(t1.id), await createTestAgent(t2.id)];
    await prisma.tenant.updateMany({ where: { id: { in: [t1.id, t2.id] } }, data: { lakeRetentionDays: 1 } });
    await write(t1.id, a1.id, 10, 1);
    await write(t2.id, a2.id, 10, 1);
    // A read-only directory: unlink of a file in it fails with EACCES, a real removal error.
    const [stuck] = await store.list(`tenant=${t1.id}/`);
    const lockedDir = path.join(dir, stuck.key.replace(/\/[^/]+$/, ""));
    const { chmod } = await import("node:fs/promises");
    await chmod(lockedDir, 0o555);
    try {
      const result = await pruneLake(prisma, store, NOW);
      expect(result).toMatchObject({ partitionsDeleted: 1, notEmpty: 1, failedPartitions: 1 });
      expect(result.errors[0]).toMatch(/not fully deleted/);
      expect(await store.list(`tenant=${t2.id}/`)).toEqual([]);
      expect((await store.list(`tenant=${t1.id}/`)).map((f) => f.key)).toEqual([stuck.key]);
      const t1row = await prisma.lakeDeletion.findFirstOrThrow({ where: { tenantId: t1.id } });
      expect(t1row).toMatchObject({ objectCount: 1, deletedCount: 0, failedCount: 1, verifiedEmpty: false });
      expect(t1row.error).toMatch(/EACCES|permission/i);
      expect(t1row.completedAt).not.toBeNull();
    } finally {
      await chmod(lockedDir, 0o755);
    }
  });

  it("runs through the cron route", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await prisma.tenant.update({ where: { id: tenant.id }, data: { lakeRetentionDays: 1 } });
    // The route uses the real clock: write a partition far enough in the past for any date today.
    const old = new Date(Date.UTC(2020, 0, 1, 12));
    await enqueueLakeBatch(prisma, { tenantId: tenant.id, agentId: agent.id, events: [event(old)], receivedAt: old });
    await drainLakeQueue(prisma, store);
    process.env.LAKE_DIR = dir;
    const res = await pruneRoute(new NextRequest("http://localhost/api/cron/prune-lake", { headers: { Authorization: "Bearer test_cron_secret" } }));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ partitionsDeleted: 1, filesDeleted: 1, notEmpty: 0 });
    expect(await readdir(dir)).toEqual([]);
    expect(await prisma.lakeDeletion.count()).toBe(1);
  });
});
