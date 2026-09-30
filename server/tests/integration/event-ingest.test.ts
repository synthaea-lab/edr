import { beforeEach, afterAll, describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { createMtlsHeaders } from "../helpers/http";
import { getPrevalence } from "@/lib/prevalence";
import { POST } from "@/app/api/v1/ingest/events/route";

const SECRET = "test-proxy-secret";
const SHA = "d".repeat(64);

function upload(enrollmentId: string, events: unknown[]) {
  return POST(
    new NextRequest("http://localhost/api/v1/ingest/events", {
      method: "POST",
      headers: { ...createMtlsHeaders(enrollmentId), "X-Proxy-Secret": SECRET },
      body: JSON.stringify({ agent_id: null, events }),
    })
  );
}

const exec = (over: Record<string, unknown> = {}) => ({
  type: "exec",
  meta: { timestamp_ns: Date.UTC(2026, 8, 2) * 1_000_000 },
  image_path: "/usr/bin/curl",
  parent_comm: "bash",
  sha256: SHA,
  ...over,
});

describe("event ingest (real database)", () => {
  beforeEach(async () => {
    process.env.NGINX_PROXY_SECRET = SECRET;
    await cleanDatabase();
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("turns a batch from two hosts into fleet prevalence, at the versioned path", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    const b = await createTestAgent(tenant.id);

    expect((await upload(a.enrollmentId, [exec(), exec()])).status).toBe(200);
    const res = await upload(b.enrollmentId, [exec({ meta: { timestamp_ns: Date.UTC(2026, 8, 20) * 1_000_000 } })]);
    expect(res.status).toBe(200);
    expect((await res.json()).accepted).toBe(1);

    const p = await getPrevalence(prisma, tenant.id, "sha256", SHA);
    expect(p).toMatchObject({
      hostCount: 2,
      eventCount: 3,
      firstSeen: new Date(Date.UTC(2026, 8, 2)),
      lastSeen: new Date(Date.UTC(2026, 8, 20)),
    });
    const transition = await getPrevalence(prisma, tenant.id, "transition", "bash -> /usr/bin/curl");
    expect(transition?.hostCount).toBe(2);
  });

  it("keeps tenants apart and marks the agent alive", async () => {
    const t1 = await createTestTenant();
    const t2 = await createTestTenant();
    const a = await createTestAgent(t1.id);
    const before = new Date(Date.now() - 60_000);
    await prisma.agent.update({ where: { id: a.id }, data: { lastSeen: before } });

    await upload(a.enrollmentId, [exec()]);

    expect(await getPrevalence(prisma, t2.id, "sha256", SHA)).toBeNull();
    const after = await prisma.agent.findUnique({ where: { id: a.id } });
    expect(after!.lastSeen.getTime()).toBeGreaterThan(before.getTime());
  });
});
