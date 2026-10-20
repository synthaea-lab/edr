import { describe, it, expect, beforeEach, afterAll, afterEach, vi } from "vitest";
import { NextRequest } from "next/server";
import {
  cleanDatabase,
  createTestTenant,
  createTestAgent,
  createTestDetection,
  prisma,
} from "../helpers/db";
import { MAX_AGENTS_PER_ENTITY } from "@/lib/fleet-case";
import { GET } from "@/app/api/cron/join-fleet-cases/route";
import { prisma as routePrisma } from "@/lib/prisma";
import { recordObservations } from "@/lib/prevalence";

const SHA = "a".repeat(64);
const OTHER_SHA = "b".repeat(64);
const exec = (sha256: string = SHA) => ({
  type: "exec",
  meta: { pid: 100, ppid: 1, comm: "payload", timestamp_ns: 1 },
  image_path: "/tmp/payload",
  sha256,
});
const session = (user: string) => ({ type: "session", target_user: user, meta: {} });

const cronRequest = (secret: string | null = process.env.CRON_SECRET ?? null) =>
  new NextRequest("http://localhost/api/cron/join-fleet-cases", {
    headers: secret ? { Authorization: `Bearer ${secret}` } : {},
  });

const T0 = Date.now() - 3_600_000;
const at = (minutes: number) => new Date(T0 + minutes * 60_000);

describe("GET /api/cron/join-fleet-cases", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  describe("a hash that most of the fleet runs", () => {
    /** `n` hosts that have all run SHA (the system shell); the first two also fired a detection on
     * it, and on OTHER_SHA (a payload only they ran). */
    async function fleetOf(n: number) {
      const tenant = await createTestTenant();
      const agents = [];
      for (let i = 0; i < n; i++) {
        const agent = await createTestAgent(tenant.id, `fleet-${i}`);
        await recordObservations(prisma, tenant.id, agent.id, at(0), [{ kind: "sha256", key: SHA }]);
        agents.push(agent);
      }
      for (const agent of agents.slice(0, 2)) {
        await recordObservations(prisma, tenant.id, agent.id, at(0), [{ kind: "sha256", key: OTHER_SHA }]);
        await createTestDetection(tenant.id, agent.id, { event: exec(SHA), timestamp: at(0) });
        await createTestDetection(tenant.id, agent.id, { event: exec(OTHER_SHA), timestamp: at(1) });
      }
      return tenant;
    }

    it("joins on the rare hash and not on the one every host has, once the fleet is big enough to tell", async () => {
      const tenant = await fleetOf(10);
      await GET(cronRequest());
      const cases = await prisma.fleetCase.findMany({ where: { tenantId: tenant.id }, include: { entities: true } });
      expect(cases).toHaveLength(1);
      expect(cases[0].entities.map((e) => e.key)).toEqual([OTHER_SHA]);
    });

    it("joins on both on a fleet of two, where a shared hash is the signal", async () => {
      const tenant = await fleetOf(2);
      await GET(cronRequest());
      const cases = await prisma.fleetCase.findMany({ where: { tenantId: tenant.id }, include: { entities: true } });
      expect(cases).toHaveLength(1);
      expect(cases[0].entities.map((e) => e.key).sort()).toEqual([SHA, OTHER_SHA].sort());
    });

    it("counts the hosts of its own tenant only", async () => {
      const tenant = await fleetOf(2);
      const other = await createTestTenant();
      for (let i = 0; i < 8; i++) {
        const agent = await createTestAgent(other.id, `other-${i}`);
        await recordObservations(prisma, other.id, agent.id, at(0), [{ kind: "sha256", key: SHA }]);
      }
      await GET(cronRequest());
      const cases = await prisma.fleetCase.findMany({ where: { tenantId: tenant.id }, include: { entities: true } });
      expect(cases[0].entities.map((e) => e.key).sort()).toEqual([SHA, OTHER_SHA].sort());
    });
  });

  it("is refused without the cron secret", async () => {
    expect((await GET(cronRequest(null))).status).toBe(401);
    expect((await GET(cronRequest("wrong"))).status).toBe(401);
  });

  it("joins the detections of two agents that carry one hash into one fleet case", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id, "agent-a");
    const b = await createTestAgent(tenant.id, "agent-b");
    const da = await createTestDetection(tenant.id, a.id, { event: exec(), severity: "medium", timestamp: at(0) });
    const db = await createTestDetection(tenant.id, b.id, { event: exec(), severity: "critical", timestamp: at(5) });

    const res = await GET(cronRequest());
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.fleetCasesCreated).toBe(1);
    expect(body.detectionsJoined).toBe(2);
    const cases = await prisma.fleetCase.findMany({ where: { tenantId: tenant.id }, include: { entities: true } });
    expect(cases).toHaveLength(1);
    expect(cases[0]).toMatchObject({ severity: "critical", status: "open", agentCount: 2 });
    expect(cases[0].firstAt).toEqual(at(0));
    expect(cases[0].lastAt).toEqual(at(5));
    expect(cases[0].entities.map((e) => [e.kind, e.key])).toEqual([["sha256", SHA]]);
    const joined = await prisma.detection.findMany({ where: { fleetCaseId: cases[0].id }, select: { id: true } });
    expect(joined.map((d) => d.id).sort()).toEqual([da.id, db.id].sort());
  });

  it("does not touch a detection's host case", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id, "agent-a");
    const b = await createTestAgent(tenant.id, "agent-b");
    const hostCase = await prisma.case.create({
      data: { tenantId: tenant.id, title: "host case", severity: "high", status: "open" },
    });
    await createTestDetection(tenant.id, a.id, { event: exec(), caseId: hostCase.id });
    await createTestDetection(tenant.id, b.id, { event: exec() });

    await GET(cronRequest());

    const kept = await prisma.detection.findMany({ where: { agentId: a.id } });
    expect(kept[0].caseId).toBe(hostCase.id);
    expect(kept[0].fleetCaseId).not.toBeNull();
  });

  it("is idempotent: a second run changes nothing", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id, "agent-a");
    const b = await createTestAgent(tenant.id, "agent-b");
    await createTestDetection(tenant.id, a.id, { event: exec() });
    await createTestDetection(tenant.id, b.id, { event: exec() });
    await GET(cronRequest());
    const before = await prisma.fleetCase.findMany({ where: { tenantId: tenant.id } });

    const body = await (await GET(cronRequest())).json();

    expect(body.fleetCasesCreated).toBe(0);
    expect(await prisma.fleetCase.findMany({ where: { tenantId: tenant.id } })).toEqual(before);
    expect(await prisma.fleetCaseEntity.count({ where: { tenantId: tenant.id } })).toBe(1);
  });

  it("grows the case when a third agent shows the same hash later, and raises its severity but never lowers it", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id, "agent-a");
    const b = await createTestAgent(tenant.id, "agent-b");
    const c = await createTestAgent(tenant.id, "agent-c");
    await createTestDetection(tenant.id, a.id, { event: exec(), severity: "high", timestamp: at(0) });
    await createTestDetection(tenant.id, b.id, { event: exec(), severity: "high", timestamp: at(1) });
    await GET(cronRequest());
    const [first] = await prisma.fleetCase.findMany({ where: { tenantId: tenant.id } });

    await createTestDetection(tenant.id, c.id, { event: exec(), severity: "low", timestamp: at(10) });
    const body = await (await GET(cronRequest())).json();

    expect(body.fleetCasesCreated).toBe(0);
    const cases = await prisma.fleetCase.findMany({ where: { tenantId: tenant.id } });
    expect(cases).toHaveLength(1);
    expect(cases[0].id).toBe(first.id);
    expect(cases[0]).toMatchObject({ agentCount: 3, severity: "high" });
    expect(cases[0].lastAt).toEqual(at(10));
  });

  it("a detection that bridges two fleet cases merges them into the older one", async () => {
    const tenant = await createTestTenant();
    const [a, b, c, d] = await Promise.all(
      ["agent-a", "agent-b", "agent-c", "agent-d"].map((n) => createTestAgent(tenant.id, n))
    );
    await createTestDetection(tenant.id, a.id, { event: exec(), timestamp: at(0) });
    await createTestDetection(tenant.id, b.id, { event: exec(), timestamp: at(1) });
    await GET(cronRequest());
    // A second run, so the identity's case is created after the hash's and is the younger.
    await createTestDetection(tenant.id, c.id, { event: session("mallory"), timestamp: at(2) });
    await createTestDetection(tenant.id, d.id, { event: session("mallory"), timestamp: at(3) });
    await GET(cronRequest());
    expect(await prisma.fleetCase.count({ where: { tenantId: tenant.id } })).toBe(2);
    const older = await prisma.fleetCase.findFirstOrThrow({
      where: { tenantId: tenant.id, entities: { some: { kind: "sha256" } } },
    });

    // Agent b also signed in as mallory, and agent c ran the hash: both entities now span all four.
    await createTestDetection(tenant.id, b.id, { event: session("mallory"), timestamp: at(4) });
    await createTestDetection(tenant.id, c.id, { event: exec(), timestamp: at(5) });
    await GET(cronRequest());

    const cases = await prisma.fleetCase.findMany({ where: { tenantId: tenant.id }, include: { entities: true } });
    expect(cases).toHaveLength(1);
    expect(cases[0].agentCount).toBe(4);
    expect(cases[0].entities.map((e) => e.kind).sort()).toEqual(["identity", "sha256"]);
    expect(cases[0].id).toBe(older.id);
    expect(await prisma.detection.count({ where: { tenantId: tenant.id, fleetCaseId: null } })).toBe(0);
  });

  it("joins nothing for one agent, and nothing across tenants", async () => {
    const t1 = await createTestTenant();
    const t2 = await createTestTenant();
    const a = await createTestAgent(t1.id, "agent-a");
    const b = await createTestAgent(t2.id, "agent-b");
    await createTestDetection(t1.id, a.id, { event: exec(), timestamp: at(0) });
    await createTestDetection(t1.id, a.id, { event: exec(), timestamp: at(1) });
    await createTestDetection(t2.id, b.id, { event: exec(), timestamp: at(2) });

    const body = await (await GET(cronRequest())).json();

    expect(body.fleetCasesCreated).toBe(0);
    expect(await prisma.fleetCase.count()).toBe(0);
  });

  it("joins nothing on a hash that is on more agents than the cap", async () => {
    const tenant = await createTestTenant();
    for (let i = 0; i <= MAX_AGENTS_PER_ENTITY; i++) {
      const agent = await createTestAgent(tenant.id, `agent-${i}`);
      await createTestDetection(tenant.id, agent.id, { event: exec(), timestamp: at(i % 10) });
    }

    const body = await (await GET(cronRequest())).json();

    expect(body.fleetCasesCreated).toBe(0);
    expect(await prisma.fleetCase.count()).toBe(0);
  });

  it("does not join on a generic account, or on a different hash", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id, "agent-a");
    const b = await createTestAgent(tenant.id, "agent-b");
    await createTestDetection(tenant.id, a.id, { event: session("root") });
    await createTestDetection(tenant.id, b.id, { event: session("root") });
    await createTestDetection(tenant.id, a.id, { event: exec(SHA) });
    await createTestDetection(tenant.id, b.id, { event: exec(OTHER_SHA) });

    await GET(cronRequest());

    expect(await prisma.fleetCase.count()).toBe(0);
  });

  it("one tenant's failure does not stop the others, and is not a 200", async () => {
    const t1 = await createTestTenant();
    const t2 = await createTestTenant();
    for (const t of [t1, t2]) {
      const a = await createTestAgent(t.id, `a-${t.id}`);
      const b = await createTestAgent(t.id, `b-${t.id}`);
      await createTestDetection(t.id, a.id, { event: exec() });
      await createTestDetection(t.id, b.id, { event: exec() });
    }
    vi.spyOn(console, "error").mockImplementation(() => {});
    const real = routePrisma.$transaction.bind(routePrisma);
    let calls = 0;
    vi.spyOn(routePrisma, "$transaction").mockImplementation(((fn: never, opts: never) => {
      calls += 1;
      return calls === 1 ? Promise.reject(new Error("boom")) : real(fn, opts);
    }) as never);

    const res = await GET(cronRequest());
    const body = await res.json();

    expect(res.status).toBe(207);
    expect(body.tenantsFailed).toBe(1);
    expect(body.fleetCasesCreated).toBe(1);
    expect(await prisma.fleetCase.count()).toBe(1);
  });
});
