import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { NextRequest } from "next/server";
import { cleanDatabase, createTestTenant, createTestAgent, prisma } from "../helpers/db";
import { GET } from "@/app/api/cron/detect-silent-agents/route";

function cronRequest() {
  return new NextRequest("http://localhost/api/cron/detect-silent-agents", {
    headers: { Authorization: `Bearer ${process.env.CRON_SECRET}` },
  });
}

const HOUR_AGO = () => new Date(Date.now() - 60 * 60 * 1000);

describe("GET /api/cron/detect-silent-agents", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("opens one case per silent agent, however many times it runs (#901)", async () => {
    const tenant = await createTestTenant();
    // `createTestAgent` gives every agent a host name, which the case title then carries.
    await createTestAgent(tenant.id, "enroll-named", { hostname: "web-01", lastSeen: HOUR_AGO() });
    await prisma.agent.create({
      data: { tenantId: tenant.id, enrollmentId: "enroll-unnamed", lastSeen: HOUR_AGO() },
    });

    const created: number[] = [];
    for (let run = 0; run < 3; run++) {
      const res = await GET(cronRequest());
      expect(res.status).toBe(200);
      created.push((await res.json()).casesCreated);
    }

    expect(created).toEqual([2, 0, 0]);
    const titles = (await prisma.case.findMany({ where: { tenantId: tenant.id } }))
      .map((c) => c.title)
      .sort();
    expect(titles).toHaveLength(2);
    expect(titles.filter((t) => t === "Agent Silent: web-01")).toHaveLength(1);
  });

  it("opens a new case once the previous one is resolved", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "enroll-named", { hostname: "web-01", lastSeen: HOUR_AGO() });

    await GET(cronRequest());
    await prisma.case.updateMany({ where: { tenantId: tenant.id }, data: { status: "resolved" } });
    const res = await GET(cronRequest());

    expect((await res.json()).casesCreated).toBe(1);
    expect(await prisma.case.count({ where: { tenantId: tenant.id } })).toBe(2);
  });
});
