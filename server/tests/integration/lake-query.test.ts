import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { FsLakeStore } from "@/lib/lake-store";
import { drainLakeQueue, enqueueLakeBatch } from "@/lib/lake-writer";
import { queryLake } from "@/lib/lake-query";
import { pruneLake } from "@/lib/lake-retention";

const DAY = 86_400_000;
const NOW = new Date(Date.UTC(2026, 9, 30, 12, 0, 0));

let dir: string;
let store: FsLakeStore;

beforeEach(async () => {
  await cleanDatabase();
  await prisma.lakeDeletion.deleteMany();
  dir = await mkdtemp(path.join(os.tmpdir(), "lake-query-int-"));
  store = new FsLakeStore(dir);
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});
afterAll(async () => {
  await prisma.lakeDeletion.deleteMany();
  await cleanDatabase();
  await prisma.$disconnect();
});

/** Uploads events dated `daysAgo` days before NOW through the real queue and writer, drained the day they happened. */
async function upload(tenantId: string, agentId: string, daysAgo: number, events: object[]) {
  const at = new Date(NOW.getTime() - daysAgo * DAY);
  const stamped = events.map((e, i) => ({ meta: { comm: "bash", timestamp_ns: at.getTime() * 1_000_000 + i * 1_000_000 }, ...e }));
  await enqueueLakeBatch(prisma, { tenantId, agentId, events: stamped, receivedAt: at });
  await drainLakeQueue(prisma, store, { now: at });
}
const day = (daysAgo: number) => new Date(NOW.getTime() - daysAgo * DAY).toISOString().slice(0, 10);

describe("uploads land partitioned and are queryable", () => {
  it("answers a hunt-style query over N days for one tenant and none of another's", async () => {
    const [t1, t2] = [await createTestTenant(), await createTestTenant()];
    const [a1, a2] = [await createTestAgent(t1.id), await createTestAgent(t2.id)];
    for (const daysAgo of [6, 5, 4, 3, 2, 1, 0]) {
      await upload(t1.id, a1.id, daysAgo, [
        { type: "exec", image_path: daysAgo === 3 ? "/tmp/dropper" : "/usr/bin/ls" },
        { type: "connect", daddr: daysAgo === 3 ? "203.0.113.9" : "198.51.100.1" },
      ]);
      await upload(t2.id, a2.id, daysAgo, [{ type: "exec", image_path: "/tmp/dropper" }]);
    }

    const week = await queryLake(store, { tenantId: t1.id, from: day(6), to: day(0), limit: 1000 });
    expect(week.rows).toHaveLength(14);
    expect(week.rows.every((r) => r.agentId === a1.id)).toBe(true);
    expect(week.rows.map((r) => r.ts.getTime())).toEqual([...week.rows.map((r) => r.ts.getTime())].sort((a, b) => a - b));

    const dropper = await queryLake(store, { tenantId: t1.id, from: day(6), to: day(0), where: { imagePath: "/tmp/dropper" } });
    expect(dropper.rows.map((r) => r.date)).toEqual([day(3)]);
    const c2 = await queryLake(store, { tenantId: t1.id, from: day(6), to: day(0), types: ["connect"], where: { daddr: "203.0.113.9" } });
    expect(c2.rows).toHaveLength(1);
    expect(JSON.parse(c2.rows[0].event)).toMatchObject({ type: "connect", daddr: "203.0.113.9" });
    expect(c2.filesMatched).toBe(7); // the exec files were pruned by the path, not read
  });

  it("no longer returns a partition once the retention job has deleted it", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await prisma.tenant.update({ where: { id: tenant.id }, data: { lakeRetentionDays: 3 } });
    await upload(tenant.id, agent.id, 5, [{ type: "exec", image_path: "/a" }]);
    await upload(tenant.id, agent.id, 1, [{ type: "exec", image_path: "/b" }]);
    expect((await queryLake(store, { tenantId: tenant.id, from: day(6), to: day(0) })).rows).toHaveLength(2);
    // Seeded through the writer one day at a time (retention is judged at drain time, #1047), so the old day exists to be deleted.
    await pruneLake(prisma, store, NOW);
    expect((await queryLake(store, { tenantId: tenant.id, from: day(6), to: day(0) })).rows.map((r) => r.imagePath)).toEqual(["/b"]);
  });
});
