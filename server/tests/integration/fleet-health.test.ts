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
  ).agents as {
    id: string;
    status: string;
    health: {
      spoolDropped: number;
      lossObservedAt: string | null;
      rarityApplied: number;
      rarityWithheld: number;
      rarityUnapplied: number;
      sensors: unknown[];
    } | null;
  }[];

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
    // The second counter is lower on purpose: a rising loss counter is recent loss and makes the
    // host degraded (#83), while this test is about the row being overwritten, not summed.
    await beat("agent-h1", { agent_id: agent.id, beacon: beacon({ spool_dropped: 9 }) });
    await beat("agent-h1", { agent_id: agent.id, beacon: beacon({ spool_dropped: 4 }) });

    expect(await prisma.agentHealth.count({ where: { agentId: agent.id } })).toBe(1);
    const [row] = await getFleet(tenant.id);
    expect(row.health?.spoolDropped).toBe(4);
    expect(row.status).toBe("healthy");
  });

  describe("recent telemetry loss (#83)", () => {
    const T0 = Date.now() * 1_000_000;
    const at = (seconds: number, over: Record<string, unknown> = {}) =>
      beacon({ timestamp_ns: T0 + seconds * 1_000_000_000, spool_dropped: 0, enrich_dropped: 0, ...over });

    it("does not degrade a host on its first beacon, even with non-zero counters", async () => {
      const tenant = await createTestTenant();
      await createTestAgent(tenant.id, "agent-l1");
      await beat("agent-l1", { beacon: at(0, { spool_dropped: 4096, enrich_dropped: 7560 }) });

      const [row] = await getFleet(tenant.id);
      expect(row.status).toBe("healthy");
      expect(row.health?.lossObservedAt).toBeNull();
    });

    it("degrades a host when a loss counter rises between two beacons, and says when", async () => {
      const tenant = await createTestTenant();
      await createTestAgent(tenant.id, "agent-l2");
      await beat("agent-l2", { beacon: at(0) });
      expect((await getFleet(tenant.id))[0].status).toBe("healthy");

      await beat("agent-l2", { beacon: at(30, { enrich_dropped: 7560 }) });

      const [row] = await getFleet(tenant.id);
      expect(row.status).toBe("degraded");
      expect(row.health?.lossObservedAt).not.toBeNull();
    });

    it("does not read an agent restart (counters back to zero) as loss, nor forget a recent one", async () => {
      const tenant = await createTestTenant();
      await createTestAgent(tenant.id, "agent-l3");
      await beat("agent-l3", { beacon: at(0) });
      await beat("agent-l3", { beacon: at(30, { spool_dropped: 4096 }) });
      const stamped = (await getFleet(tenant.id))[0].health?.lossObservedAt;

      await beat("agent-l3", { beacon: at(60, { spool_dropped: 0 }) }); // restart: counters reset

      const [row] = await getFleet(tenant.id);
      expect(row.health?.lossObservedAt).toBe(stamped);
      expect(row.status).toBe("degraded"); // the loss is still recent
    });

    it("is healthy again once the loss is older than the window", async () => {
      const tenant = await createTestTenant();
      const agent = await createTestAgent(tenant.id, "agent-l4");
      await beat("agent-l4", { beacon: at(0) });
      await beat("agent-l4", { beacon: at(30, { spool_dropped: 1 }) });
      expect((await getFleet(tenant.id))[0].status).toBe("degraded");

      await prisma.agentHealth.update({
        where: { agentId: agent.id },
        data: { lossObservedAt: new Date(Date.now() - 11 * 60_000) },
      });

      expect((await getFleet(tenant.id))[0].status).toBe("healthy");
    });

    it("never degrades a host for the rarity evidence counters, which are not lost telemetry", async () => {
      const tenant = await createTestTenant();
      await createTestAgent(tenant.id, "agent-l5");
      await beat("agent-l5", { beacon: at(0) });
      await beat("agent-l5", { beacon: at(30, { rarity_applied: 9, rarity_withheld: 90, rarity_unapplied: 3 }) });
      expect((await getFleet(tenant.id))[0].status).toBe("healthy");
    });

    it("ignores a beacon older than the stored one instead of storing its lower counters", async () => {
      const tenant = await createTestTenant();
      const agent = await createTestAgent(tenant.id, "agent-l6");
      await beat("agent-l6", { beacon: at(60, { spool_dropped: 50 }) });
      await beat("agent-l6", { beacon: at(0, { spool_dropped: 5 }) }); // delivered late

      const row = await prisma.agentHealth.findUniqueOrThrow({ where: { agentId: agent.id } });
      expect(Number(row.spoolDropped)).toBe(50);
      await beat("agent-l6", { beacon: at(90, { spool_dropped: 50 }) });
      expect((await getFleet(tenant.id))[0].status).toBe("healthy"); // no false loss from the late one
    });
  });

  it("stores the rarity evidence counters and shows them in the fleet view (ADR-0020, #76)", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-h5");
    await beat("agent-h5", {
      beacon: beacon({ rarity_applied: 7, rarity_withheld: 11, rarity_unapplied: 2 }),
    });

    const [row] = await getFleet(tenant.id);
    expect(row.health).toMatchObject({ rarityApplied: 7, rarityWithheld: 11, rarityUnapplied: 2 });
  });

  it("stores the beacon of an agent that predates the rarity counters, with zeros", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-h6");
    await beat("agent-h6", { beacon: beacon() });

    const [row] = await getFleet(tenant.id);
    expect(row.health).toMatchObject({ rarityApplied: 0, rarityWithheld: 0, rarityUnapplied: 0 });
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
