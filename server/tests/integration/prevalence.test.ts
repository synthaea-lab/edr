import { beforeEach, afterAll, describe, expect, it } from "vitest";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { getPrevalence, recordObservations } from "@/lib/prevalence";

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
});
