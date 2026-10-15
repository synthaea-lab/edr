import { beforeEach, afterAll, describe, expect, it } from "vitest";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { getCommonHashes, countReportingHosts, recordObservations } from "@/lib/prevalence";

const hash = (c: string) => c.repeat(64);
const sha = (c: string) => [{ kind: "sha256" as const, key: hash(c) }];

describe("common-set queries (real database)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("returns the hashes seen on at least K distinct hosts, not K events", async () => {
    const tenant = await createTestTenant();
    const [a, b, c] = [
      await createTestAgent(tenant.id),
      await createTestAgent(tenant.id),
      await createTestAgent(tenant.id),
    ];
    const at = new Date();
    for (const agent of [a, b, c]) await recordObservations(prisma, tenant.id, agent.id, at, sha("a"));
    for (const agent of [a, b]) await recordObservations(prisma, tenant.id, agent.id, at, sha("b"));
    // One host, many events: still one host.
    for (let i = 0; i < 5; i++) await recordObservations(prisma, tenant.id, a.id, at, sha("c"));
    // Not a hash kind.
    await recordObservations(prisma, tenant.id, a.id, at, [{ kind: "domain", key: "x.example" }]);
    await recordObservations(prisma, tenant.id, b.id, at, [{ kind: "domain", key: "x.example" }]);

    const { hashes, truncated } = await getCommonHashes(prisma, tenant.id, 2, 100);
    expect([...hashes].sort()).toEqual([hash("a"), hash("b")]);
    expect(truncated).toBe(false);
    expect((await getCommonHashes(prisma, tenant.id, 3, 100)).hashes).toEqual([hash("a")]);
  });

  it("reports truncation instead of silently dropping members when over the limit", async () => {
    const tenant = await createTestTenant();
    const [a, b] = [await createTestAgent(tenant.id), await createTestAgent(tenant.id)];
    for (const c of ["a", "b", "c"]) {
      for (const agent of [a, b]) await recordObservations(prisma, tenant.id, agent.id, new Date(), sha(c));
    }
    const result = await getCommonHashes(prisma, tenant.id, 2, 2);
    expect(result.hashes).toHaveLength(2);
    expect(result.truncated).toBe(true);
  });

  it("counts the hosts that reported anything, and only this tenant's", async () => {
    const t1 = await createTestTenant();
    const t2 = await createTestTenant();
    const [a, b] = [await createTestAgent(t1.id), await createTestAgent(t1.id)];
    const other = await createTestAgent(t2.id);
    await createTestAgent(t1.id); // enrolled, never reported
    await recordObservations(prisma, t1.id, a.id, new Date(), sha("a"));
    await recordObservations(prisma, t1.id, b.id, new Date(), [{ kind: "domain", key: "y.example" }]);
    await recordObservations(prisma, t2.id, other.id, new Date(), sha("a"));

    expect(await countReportingHosts(prisma, t1.id)).toBe(2);
    expect(await countReportingHosts(prisma, t2.id)).toBe(1);
    expect((await getCommonHashes(prisma, t2.id, 2, 100)).hashes).toEqual([]);
  });
});
