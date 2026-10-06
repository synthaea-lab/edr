import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { NextRequest } from "next/server";
import { cleanDatabase, createTestTenant, createTestAgent, prisma } from "../helpers/db";
import { createTenantHeaders } from "../helpers/http";
import { GET as rings } from "@/app/api/ops/rings/route";
import { GET as ringHealth } from "@/app/api/rings/[ring]/health/route";

async function release(tenantId: string, ring: string, version: number, status: string) {
  await prisma.contentRelease.create({
    data: {
      tenantId,
      ring,
      releaseVersion: version,
      manifestUrl: `storage://manifests/content-${ring}-v${version}.json`,
      manifestSha256: "a".repeat(64),
      status,
      releasedAt: new Date(),
    },
  });
}

const getRings = async (tenantId: string) =>
  (
    await (
      await rings(new NextRequest("http://localhost/api/ops/rings", { headers: createTenantHeaders(tenantId) }))
    ).json()
  ).rings as { ring: string; rollout: string; latestVersion: number | null; servedVersion: number | null; agents: number }[];

const getRingHealth = async (tenantId: string, ring: string) =>
  ringHealth(
    new NextRequest(`http://localhost/api/rings/${ring}/health`, { headers: createTenantHeaders(tenantId) }),
    { params: { ring } }
  );

describe("ring status against a real database (issue #83)", () => {
  beforeEach(cleanDatabase);

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("stops serving a halted release and reports it in both ring status endpoints", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-r1", { ring: "canary_0" });
    await release(tenant.id, "canary_0", 1, "active");
    await release(tenant.id, "canary_0", 2, "halted");

    const ring = (await getRings(tenant.id)).find((r) => r.ring === "canary_0");
    expect(ring).toMatchObject({ rollout: "halted", latestVersion: 2, servedVersion: null, agents: 1 });

    const health = await getRingHealth(tenant.id, "canary_0");
    expect(health.status).toBe(200);
    expect((await health.json()).contentRelease).toMatchObject({ releaseVersion: 2, status: "halted" });
  });

  it("does not show another tenant's releases or agents", async () => {
    const mine = await createTestTenant();
    const other = await createTestTenant();
    await createTestAgent(other.id, "agent-r2", { ring: "prod" });
    await release(other.id, "prod", 7, "active");

    const prod = (await getRings(mine.id)).find((r) => r.ring === "prod");
    expect(prod).toMatchObject({ rollout: "no_release", latestVersion: null, agents: 0 });
  });

  it("always lists the four rings", async () => {
    const tenant = await createTestTenant();
    expect((await getRings(tenant.id)).map((r) => r.ring)).toEqual(["canary_0", "canary_1", "canary_2", "prod"]);
  });
});
