import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import {
  cleanDatabase,
  createTestAgent,
  createTestCase,
  createTestDetection,
  createTestTenant,
  prisma,
} from "../helpers/db";
import { createTenantHeaders } from "../helpers/http";
import { GET as getCaseGraph } from "@/app/api/cases/[id]/graph/route";
import { GET as getPivot } from "@/app/api/graph/pivot/route";

const SHA = "b".repeat(64);

describe("GET /api/cases/[id]/graph", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("renders a case's subgraph from its detections, not from other cases' or tenants'", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const case_ = await createTestCase(tenant.id);
    await createTestDetection(tenant.id, agent.id, {
      caseId: case_.id,
      event: {
        type: "exec",
        meta: { pid: 100, ppid: 1, comm: "curl", timestamp_ns: 1 },
        image_path: "/usr/bin/curl",
        sha256: SHA,
        parent_comm: "bash",
      },
    });
    // Another case, another tenant: neither must leak into this one's subgraph.
    const otherCase = await createTestCase(tenant.id);
    await createTestDetection(tenant.id, agent.id, {
      caseId: otherCase.id,
      event: { type: "exec", meta: { pid: 200, ppid: 1, comm: "sh" }, image_path: "/bin/sh" },
    });
    const otherTenant = await createTestTenant();
    const otherAgent = await createTestAgent(otherTenant.id);
    await createTestDetection(otherTenant.id, otherAgent.id, {
      caseId: case_.id, // ignored: cases are per-tenant, this id does not resolve under otherTenant
      event: { type: "exec", meta: { pid: 300, ppid: 1, comm: "powershell" }, image_path: "/evil.exe" },
    });

    const req = new NextRequest("http://localhost/api/cases/x/graph", {
      headers: createTenantHeaders(tenant.id),
    });
    const body = await (await getCaseGraph(req, { params: { id: case_.id } })).json();

    expect(body.nodes.map((n: { kind: string }) => n.kind).sort()).toEqual(
      ["file", "host", "process", "process"].sort()
    );
    expect(body.nodes.some((n: { label: string }) => n.label === "/bin/sh")).toBe(false);
    expect(body.nodes.some((n: { label: string }) => n.label === "/evil.exe")).toBe(false);
  });

  it("404s a case id that does not resolve under the caller's tenant", async () => {
    const tenant = await createTestTenant();
    const other = await createTestTenant();
    const otherCase = await createTestCase(other.id);
    const req = new NextRequest("http://localhost/api/cases/x/graph", {
      headers: createTenantHeaders(tenant.id),
    });
    const res = await getCaseGraph(req, { params: { id: otherCase.id } });
    expect(res.status).toBe(404);
  });
});

describe("GET /api/graph/pivot", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("returns one host node per agent that showed the hash, scoped to the caller's tenant", async () => {
    const tenant = await createTestTenant();
    const a1 = await createTestAgent(tenant.id);
    const a2 = await createTestAgent(tenant.id);
    const other = await createTestTenant();
    const a3 = await createTestAgent(other.id);
    const now = new Date();
    for (const agentId of [a1.id, a2.id, a3.id]) {
      await prisma.prevalenceSighting.create({
        data: { tenantId: agentId === a3.id ? other.id : tenant.id, agentId, kind: "sha256", key: SHA, firstSeen: now, lastSeen: now, count: 1 },
      });
    }

    const req = new NextRequest(`http://localhost/api/graph/pivot?kind=sha256&key=${SHA}`, {
      headers: createTenantHeaders(tenant.id),
    });
    const body = await (await getPivot(req)).json();

    expect(body.nodes).toHaveLength(3); // 1 file + a1 + a2, never a3 (other tenant)
    const hostKeys = body.nodes.filter((n: { kind: string }) => n.kind === "host").map((n: { key: string }) => n.key);
    expect(hostKeys.sort()).toEqual([a1.id, a2.id].sort());
  });

  it("an unseen key returns an empty graph, not a 404", async () => {
    const tenant = await createTestTenant();
    const req = new NextRequest(`http://localhost/api/graph/pivot?kind=sha256&key=${"c".repeat(64)}`, {
      headers: createTenantHeaders(tenant.id),
    });
    const res = await getPivot(req);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ nodes: [], edges: [] });
  });

  it("rejects an invalid kind", async () => {
    const tenant = await createTestTenant();
    const req = new NextRequest("http://localhost/api/graph/pivot?kind=nope&key=x", {
      headers: createTenantHeaders(tenant.id),
    });
    expect((await getPivot(req)).status).toBe(400);
  });
});
