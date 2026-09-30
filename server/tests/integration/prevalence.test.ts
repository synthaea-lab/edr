import { beforeEach, afterAll, describe, expect, it } from "vitest";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import {
  aggregateSightings,
  getPrevalence,
  recordObservations,
  recordSightings,
} from "@/lib/prevalence";

const OBS = [{ kind: "sha256" as const, key: "b".repeat(64) }];

describe("prevalence counters (real database)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("counts distinct hosts, not events", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    const b = await createTestAgent(tenant.id);
    const day = (d: number) => new Date(Date.UTC(2026, 8, d));
    await recordObservations(prisma, tenant.id, a.id, day(1), OBS);
    await recordObservations(prisma, tenant.id, a.id, day(2), OBS);
    await recordObservations(prisma, tenant.id, b.id, day(3), OBS);

    const p = await getPrevalence(prisma, tenant.id, "sha256", OBS[0].key);
    expect(p).toMatchObject({ hostCount: 2, eventCount: 3, firstSeen: day(1), lastSeen: day(3) });
  });

  it("never moves first_seen later when an old event arrives after a new one", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    await recordObservations(prisma, tenant.id, a.id, new Date(Date.UTC(2026, 8, 20)), OBS);
    await recordObservations(prisma, tenant.id, a.id, new Date(Date.UTC(2026, 8, 5)), OBS);

    const p = await getPrevalence(prisma, tenant.id, "sha256", OBS[0].key);
    expect(p?.firstSeen).toEqual(new Date(Date.UTC(2026, 8, 5)));
    expect(p?.lastSeen).toEqual(new Date(Date.UTC(2026, 8, 20)));
  });

  it("keeps tenants apart", async () => {
    const t1 = await createTestTenant();
    const t2 = await createTestTenant();
    const a = await createTestAgent(t1.id);
    await recordObservations(prisma, t1.id, a.id, new Date(), OBS);

    expect(await getPrevalence(prisma, t2.id, "sha256", OBS[0].key)).toBeNull();
  });

  it("adds a batch's counts to what the agent already had", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    const k = { kind: "domain" as const, key: "batch.example" };
    await recordObservations(prisma, tenant.id, a.id, new Date(Date.UTC(2026, 8, 10)), [k]);
    const batch = [3, 1, 2].map((d) => ({ at: new Date(Date.UTC(2026, 8, d)), observations: [k] }));
    await recordSightings(prisma, tenant.id, a.id, aggregateSightings(batch));

    const p = await getPrevalence(prisma, tenant.id, "domain", k.key);
    expect(p).toMatchObject({
      hostCount: 1,
      eventCount: 4,
      firstSeen: new Date(Date.UTC(2026, 8, 1)),
      lastSeen: new Date(Date.UTC(2026, 8, 10)),
    });
  });

  it("writes more rows than one statement carries", async () => {
    // Crosses the per-statement row chunk (1000), so the second statement runs too.
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    const at = new Date(Date.UTC(2026, 8, 5));
    const observations = Array.from({ length: 1500 }, (_, i) => ({
      kind: "domain" as const,
      key: `bulk-${i}.example`,
    }));
    await recordSightings(prisma, tenant.id, a.id, aggregateSightings([{ at, observations }]));

    expect(await prisma.prevalenceSighting.count({ where: { tenantId: tenant.id } })).toBe(1500);
  });
});
