import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { NextRequest } from "next/server";
import {
  cleanDatabase,
  createTestTenant,
  createTestAgent,
  createTestCase,
  createTestDetection,
  createTestCaseNarrative,
  prisma,
} from "../helpers/db";
import { createTenantHeaders } from "../helpers/http";
import { GET } from "@/app/api/cases/[id]/route";

function request(tenantId: string) {
  return new NextRequest("http://localhost/api/cases/x", {
    headers: createTenantHeaders(tenantId),
  });
}

describe("GET /api/cases/[id]", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("returns the case with its grouped detections", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const case_ = await createTestCase(tenant.id, { title: "T1059.001 activity" });
    await createTestDetection(tenant.id, agent.id, { caseId: case_.id });
    await createTestDetection(tenant.id, agent.id, { caseId: case_.id });
    await createTestDetection(tenant.id, agent.id, { caseId: null }); // ungrouped, excluded

    const res = await GET(request(tenant.id), { params: { id: case_.id } });
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.case.id).toBe(case_.id);
    expect(body.detections).toHaveLength(2);
  });

  it("returns narrative: null when no narrative has been generated", async () => {
    const tenant = await createTestTenant();
    const case_ = await createTestCase(tenant.id);

    const res = await GET(request(tenant.id), { params: { id: case_.id } });
    const body = await res.json();

    expect(body.narrative).toBeNull();
  });

  it("marks the narrative stale when a newer detection was attached after generation", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const case_ = await createTestCase(tenant.id);
    const oldGeneratedAt = new Date(Date.now() - 60_000);
    await createTestCaseNarrative(tenant.id, case_.id, { generatedAt: oldGeneratedAt });
    await createTestDetection(tenant.id, agent.id, { caseId: case_.id });

    const res = await GET(request(tenant.id), { params: { id: case_.id } });
    const body = await res.json();

    expect(body.narrative.stale).toBe(true);
  });

  it("marks the narrative stale when an older detection is grouped into the case after generation", async () => {
    // Regression test: the cron sweep (group-detections) can attach an
    // already-ingested, already-old detection to a case well after a
    // narrative was generated for it. Staleness must key off when the
    // detection last changed (updatedAt, bumped by that grouping update),
    // not when it was first ingested (createdAt) — otherwise a narrative
    // silently omits evidence it was never shown.
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const case_ = await createTestCase(tenant.id);

    // Detection exists, ungrouped, before the narrative is generated.
    const detection = await createTestDetection(tenant.id, agent.id, { caseId: null });
    await createTestCaseNarrative(tenant.id, case_.id, { generatedAt: new Date() });

    // Only grouped into the case afterwards, e.g. by the cron sweep.
    await prisma.detection.update({ where: { id: detection.id }, data: { caseId: case_.id } });

    const res = await GET(request(tenant.id), { params: { id: case_.id } });
    const body = await res.json();

    expect(body.narrative.stale).toBe(true);
  });

  it("does not mark the narrative stale when no detection changed after generation", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const case_ = await createTestCase(tenant.id);
    await createTestDetection(tenant.id, agent.id, { caseId: case_.id });

    await createTestCaseNarrative(tenant.id, case_.id, { generatedAt: new Date() });

    const res = await GET(request(tenant.id), { params: { id: case_.id } });
    const body = await res.json();

    expect(body.narrative.stale).toBe(false);
  });

  it("returns 404 for a case belonging to another tenant", async () => {
    const tenant1 = await createTestTenant("Tenant 1");
    const tenant2 = await createTestTenant("Tenant 2");
    const case_ = await createTestCase(tenant2.id);

    const res = await GET(request(tenant1.id), { params: { id: case_.id } });

    expect(res.status).toBe(404);
  });
});
