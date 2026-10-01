import { beforeEach, afterAll, describe, expect, it } from "vitest";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import {
  getPrevalenceBatch,
  prevalenceKey,
  prunePrevalence,
  recordObservations,
} from "@/lib/prevalence";

const day = (d: number) => new Date(Date.UTC(2026, 8, d));
const domain = (n: number) => ({ kind: "domain" as const, key: `d${n}.example` });

async function seed(tenantId: string, agentId: string, n: number, at: Date) {
  for (let i = 0; i < n; i++) await recordObservations(prisma, tenantId, agentId, at, [domain(i)]);
}

describe("prevalence batch lookup and pruning (real database)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("looks several keys up at once and only within the tenant", async () => {
    const t1 = await createTestTenant();
    const t2 = await createTestTenant();
    const a = await createTestAgent(t1.id);
    const b = await createTestAgent(t1.id);
    const other = await createTestAgent(t2.id);
    await recordObservations(prisma, t1.id, a.id, day(2), [domain(1), domain(2)]);
    await recordObservations(prisma, t1.id, b.id, day(9), [domain(1)]);
    await recordObservations(prisma, t2.id, other.id, day(1), [domain(1), domain(3)]);

    const found = await getPrevalenceBatch(prisma, t1.id, [domain(1), domain(2), domain(3)]);

    expect(found.get(prevalenceKey("domain", "d1.example"))).toMatchObject({
      hostCount: 2,
      firstSeen: day(2),
      lastSeen: day(9),
    });
    expect(found.get(prevalenceKey("domain", "d2.example"))?.hostCount).toBe(1);
    expect(found.has(prevalenceKey("domain", "d3.example"))).toBe(false); // only the other tenant saw it
  });

  it("drops sightings not renewed since the cutoff and keeps the recent ones", async () => {
    const t = await createTestTenant();
    const a = await createTestAgent(t.id);
    await recordObservations(prisma, t.id, a.id, day(1), [domain(1)]);
    await recordObservations(prisma, t.id, a.id, day(25), [domain(2)]);

    const r = await prunePrevalence(prisma, { olderThan: day(10), maxRowsPerTenant: 1000 });

    expect(r).toEqual({ expired: 1, overCap: 0 });
    const left = await prisma.prevalenceSighting.findMany({ where: { tenantId: t.id } });
    expect(left.map((s) => s.key)).toEqual(["d2.example"]);
  });

  it("trims a tenant over the cap to its newest rows and leaves other tenants alone", async () => {
    const big = await createTestTenant();
    const small = await createTestTenant();
    const ba = await createTestAgent(big.id);
    const sa = await createTestAgent(small.id);
    for (let i = 0; i < 6; i++) {
      await recordObservations(prisma, big.id, ba.id, day(10 + i), [domain(i)]); // d0 oldest … d5 newest
    }
    await seed(small.id, sa.id, 3, day(1));

    const r = await prunePrevalence(prisma, { olderThan: day(1), maxRowsPerTenant: 4 });

    expect(r.overCap).toBe(2);
    const kept = await prisma.prevalenceSighting.findMany({
      where: { tenantId: big.id },
      orderBy: { key: "asc" },
    });
    expect(kept.map((s) => s.key)).toEqual(["d2.example", "d3.example", "d4.example", "d5.example"]);
    expect(await prisma.prevalenceSighting.count({ where: { tenantId: small.id } })).toBe(3);
  });
});
