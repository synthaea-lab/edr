import { describe, it, expect, beforeEach, afterAll, vi } from "vitest";
import { NextRequest } from "next/server";
import {
  cleanDatabase,
  createTestTenant,
  createTestAgent,
  createTestCase,
  createTestDetection,
  prisma,
} from "../helpers/db";
import { createTenantHeaders } from "../helpers/http";

const { generateNarrative } = vi.hoisted(() => ({ generateNarrative: vi.fn() }));

vi.mock("@/assistant/llm-client", async () => {
  const actual =
    await vi.importActual<typeof import("@/assistant/llm-client")>("@/assistant/llm-client");
  return { ...actual, generateNarrative };
});

import { POST } from "@/app/api/cases/[id]/narrative/regenerate/route";

function request(tenantId: string) {
  return new NextRequest("http://localhost/api/cases/x/narrative/regenerate", {
    method: "POST",
    headers: createTenantHeaders(tenantId, "analyst-1"),
  });
}

describe("POST /api/cases/[id]/narrative/regenerate", () => {
  beforeEach(async () => {
    await cleanDatabase();
    generateNarrative.mockReset();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("creates a CaseNarrative row citing only detectionIds present on the case", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const case_ = await createTestCase(tenant.id);
    const detection = await createTestDetection(tenant.id, agent.id, { caseId: case_.id });

    generateNarrative.mockResolvedValue({
      text: "A suspicious process ran.",
      citations: [{ detectionId: detection.id, claim: "suspicious process" }],
      model: "test-model",
      provider: "self-hosted",
      promptVersion: 1,
    });

    const res = await POST(request(tenant.id), { params: { id: case_.id } });
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.narrative.narrative).toBe("A suspicious process ran.");
    expect(body.narrative.citations).toEqual([
      { detectionId: detection.id, claim: "suspicious process" },
    ]);

    const stored = await prisma.caseNarrative.findFirst({ where: { caseId: case_.id } });
    expect(stored?.generatedBy).toBe("user:analyst-1");
  });

  it("writes a case.narrative.generate audit log entry", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const case_ = await createTestCase(tenant.id);
    await createTestDetection(tenant.id, agent.id, { caseId: case_.id });

    generateNarrative.mockResolvedValue({
      text: "Narrative.",
      citations: [],
      model: "test-model",
      provider: "self-hosted",
      promptVersion: 1,
    });

    await POST(request(tenant.id), { params: { id: case_.id } });

    const auditLog = await prisma.auditLog.findFirst({
      where: { tenantId: tenant.id, action: "case.narrative.generate" },
    });
    expect(auditLog?.resource).toBe(`cases/${case_.id}`);
    expect(auditLog?.userId).toBe("analyst-1");
  });

  it("returns 400 for a case with no detections", async () => {
    const tenant = await createTestTenant();
    const case_ = await createTestCase(tenant.id);

    const res = await POST(request(tenant.id), { params: { id: case_.id } });

    expect(res.status).toBe(400);
    expect(generateNarrative).not.toHaveBeenCalled();
  });

  it("returns 502 without writing a narrative row when the LLM call fails", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const case_ = await createTestCase(tenant.id);
    await createTestDetection(tenant.id, agent.id, { caseId: case_.id });

    const { NarrativeGenerationError } =
      await vi.importActual<typeof import("@/assistant/llm-client")>("@/assistant/llm-client");
    generateNarrative.mockRejectedValue(new NarrativeGenerationError("boom"));

    const res = await POST(request(tenant.id), { params: { id: case_.id } });

    expect(res.status).toBe(502);
    const stored = await prisma.caseNarrative.findFirst({ where: { caseId: case_.id } });
    expect(stored).toBeNull();
  });
});
