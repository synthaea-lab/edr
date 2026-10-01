import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { NextRequest } from "next/server";
import { cleanDatabase, createTestTenant, createTestAgent, prisma } from "../helpers/db";
import { createMtlsHeaders, createTenantHeaders } from "../helpers/http";
import { POST as heartbeat } from "@/app/api/ingest/heartbeat/route";
import { GET as fleet } from "@/app/api/ops/fleet/route";

const SECRET = "integration-proxy-secret";

const beacon = (over: Record<string, unknown> = {}) => ({
  timestamp_ns: Date.now() * 1_000_000,
  agent_version: "0.1.0",
  sensors: [{ name: "linux-ebpf", pulse_count: 10, silent: false }],
  spool_bytes: 100,
  spool_dropped: 2,
  enrich_dropped: 3,
  ...over,
});

const beat = (enrollmentId: string, body?: unknown) =>
  heartbeat(
    new NextRequest("http://localhost/api/ingest/heartbeat", {
      method: "POST",
      headers: { ...createMtlsHeaders(enrollmentId), "X-Proxy-Secret": SECRET },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  );

const getFleet = async (tenantId: string) =>
  (
    await (
      await fleet(
        new NextRequest("http://localhost/api/ops/fleet", { headers: createTenantHeaders(tenantId) })
      )
    ).json()
  ).agents as { id: string; status: string; health: { spoolDropped: number; sensors: unknown[] } | null }[];

describe("fleet health against a real database (issue #83)", () => {
  beforeEach(async () => {
    process.env.NGINX_PROXY_SECRET = SECRET;
    await cleanDatabase();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("keeps the latest beacon per agent, overwriting rather than accumulating", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id, "agent-h1");
    await beat("agent-h1", { agent_id: agent.id, beacon: beacon({ spool_dropped: 2 }) });
    await beat("agent-h1", { agent_id: agent.id, beacon: beacon({ spool_dropped: 9 }) });

    expect(await prisma.agentHealth.count({ where: { agentId: agent.id } })).toBe(1);
    const [row] = await getFleet(tenant.id);
    expect(row.health?.spoolDropped).toBe(9);
    expect(row.status).toBe("healthy");
  });

  it("shows an agent whose sensor went silent as degraded", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-h2");
    await beat("agent-h2", {
      beacon: beacon({ sensors: [{ name: "linux-ebpf", pulse_count: 4, silent: true }] }),
    });
    expect((await getFleet(tenant.id))[0].status).toBe("degraded");
  });

  it("still counts a heartbeat with no or a malformed beacon as liveness", async () => {
    const tenant = await createTestTenant();
    const old = new Date(Date.now() - 3_600_000);
    const agent = await createTestAgent(tenant.id, "agent-h3", { lastSeen: old });
    expect((await beat("agent-h3")).status).toBe(200);
    expect((await beat("agent-h3", { beacon: { timestamp_ns: "soon" } })).status).toBe(200);

    const after = await prisma.agent.findUniqueOrThrow({ where: { id: agent.id } });
    expect(after.lastSeen.getTime()).toBeGreaterThan(old.getTime());
    expect(await prisma.agentHealth.count()).toBe(0);
    expect((await getFleet(tenant.id))[0].status).toBe("no_beacon");
  });

  it("lists silent agents first and never another tenant's agents", async () => {
    const mine = await createTestTenant();
    const other = await createTestTenant();
    const silent = await createTestAgent(mine.id, "agent-h4", { lastSeen: new Date(Date.now() - 3_600_000) });
    await createTestAgent(mine.id, "agent-h5");
    await createTestAgent(other.id, "agent-h6");

    const agents = await getFleet(mine.id);
    expect(agents).toHaveLength(2);
    expect(agents[0].id).toBe(silent.id);
    expect(agents[0].status).toBe("silent");
  });

  it("removes an agent's health with the agent", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id, "agent-h7");
    await beat("agent-h7", { beacon: beacon() });
    await prisma.agent.delete({ where: { id: agent.id } });
    expect(await prisma.agentHealth.count()).toBe(0);
  });
});
