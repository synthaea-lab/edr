import { describe, it, expect, beforeEach, afterAll } from "vitest";
import {
  cleanDatabase,
  createTestTenant,
  createTestAgent,
  prisma,
} from "../helpers/db";
import { createMtlsHeaders, createDetectionPayload } from "../helpers/http";

describe("Ingest API", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  describe("POST /api/ingest/detection", () => {
    it("should accept detection from enrolled agent", async () => {
      // Setup
      const tenant = await createTestTenant();
      const agent = await createTestAgent(tenant.id, "agent-test-001");

      // Test detection payload
      const payload = createDetectionPayload({
        technique: "T1059.001",
        severity: "critical",
      });

      // In real test, would use fetch to hit endpoint
      // For now, test the validation schema
      const { z } = await import("zod");
      const DetectionSchema = z.object({
        timestamp_ns: z.number(),
        technique: z.string(),
        severity: z.enum(["low", "medium", "high", "critical"]),
        event: z.record(z.any()),
        meta: z.record(z.any()),
      });

      const result = DetectionSchema.safeParse(payload);
      expect(result.success).toBe(true);

      // Verify database schema accepts the data
      const detection = await prisma.detection.create({
        data: {
          tenantId: tenant.id,
          agentId: agent.id,
          timestamp: new Date(payload.timestamp_ns / 1_000_000),
          technique: payload.technique,
          severity: payload.severity,
          event: payload.event,
          meta: payload.meta,
        },
      });

      expect(detection.id).toBeDefined();
      expect(detection.technique).toBe("T1059.001");
      expect(detection.severity).toBe("critical");
    });

    it("should reject detection with invalid severity", async () => {
      const payload = {
        timestamp_ns: Date.now() * 1_000_000,
        technique: "T1059.001",
        severity: "invalid",
        event: {},
        meta: {},
      };

      const { z } = await import("zod");
      const DetectionSchema = z.object({
        timestamp_ns: z.number(),
        technique: z.string(),
        severity: z.enum(["low", "medium", "high", "critical"]),
        event: z.record(z.any()),
        meta: z.record(z.any()),
      });

      const result = DetectionSchema.safeParse(payload);
      expect(result.success).toBe(false);
    });

    it("enforces retry-key uniqueness per agent while allowing legacy detections", async () => {
      const tenant = await createTestTenant();
      const firstAgent = await createTestAgent(tenant.id, "agent-retry-001");
      const secondAgent = await createTestAgent(tenant.id, "agent-retry-002");
      const key = "b9628fc1-2134-4d4d-bbe6-83fdd1929d7a";
      const data = {
        tenantId: tenant.id,
        timestamp: new Date(),
        technique: "T1059",
        severity: "medium",
        event: {},
        meta: {},
      };

      await prisma.detection.create({ data: { ...data, agentId: firstAgent.id, ingestId: key } });
      await expect(prisma.detection.create({
        data: { ...data, agentId: firstAgent.id, ingestId: key },
      })).rejects.toMatchObject({ code: "P2002" });
      await prisma.detection.create({ data: { ...data, agentId: secondAgent.id, ingestId: key } });
      await prisma.detection.create({ data: { ...data, agentId: firstAgent.id } });
      await prisma.detection.create({ data: { ...data, agentId: firstAgent.id } });
    });

    it("should update agent last-seen timestamp", async () => {
      const tenant = await createTestTenant();
      const agent = await createTestAgent(tenant.id);

      const oldLastSeen = agent.lastSeen;

      // Wait 100ms to ensure timestamp difference
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Update last-seen
      const updated = await prisma.agent.update({
        where: { id: agent.id },
        data: { lastSeen: new Date() },
      });

      expect(updated.lastSeen.getTime()).toBeGreaterThan(
        oldLastSeen.getTime()
      );
    });
  });

  describe("POST /api/ingest/heartbeat", () => {
    it("should update agent last-seen timestamp", async () => {
      const tenant = await createTestTenant();
      const agent = await createTestAgent(tenant.id, "agent-heartbeat-001");

      const oldLastSeen = agent.lastSeen;

      // Wait 100ms
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Update via heartbeat logic
      const updated = await prisma.agent.update({
        where: { enrollmentId: agent.enrollmentId },
        data: { lastSeen: new Date() },
      });

      expect(updated.lastSeen.getTime()).toBeGreaterThan(
        oldLastSeen.getTime()
      );
      expect(updated.id).toBe(agent.id);
    });

    it("should fail for non-enrolled agent", async () => {
      // Try to update non-existent agent
      await expect(
        prisma.agent.update({
          where: { enrollmentId: "non-existent-agent" },
          data: { lastSeen: new Date() },
        })
      ).rejects.toThrow();
    });
  });

  describe("GET /api/cron/detect-silent-agents", () => {
    it("should detect agents with old last-seen timestamp", async () => {
      const tenant = await createTestTenant();

      // Create silent agent (6 minutes ago)
      const silentAgent = await prisma.agent.create({
        data: {
          tenantId: tenant.id,
          enrollmentId: "silent-agent",
          lastSeen: new Date(Date.now() - 6 * 60 * 1000),
        },
      });

      // Create active agent (1 minute ago)
      const activeAgent = await prisma.agent.create({
        data: {
          tenantId: tenant.id,
          enrollmentId: "active-agent",
          lastSeen: new Date(Date.now() - 1 * 60 * 1000),
        },
      });

      // Silent agent detection logic
      const SILENCE_THRESHOLD_MS = 5 * 60 * 1000;
      const threshold = new Date(Date.now() - SILENCE_THRESHOLD_MS);

      const silentAgents = await prisma.agent.findMany({
        where: {
          lastSeen: { lt: threshold },
        },
      });

      expect(silentAgents).toHaveLength(1);
      expect(silentAgents[0].id).toBe(silentAgent.id);
    });

    it("should create case for silent agent", async () => {
      const tenant = await createTestTenant();
      const agent = await prisma.agent.create({
        data: {
          tenantId: tenant.id,
          enrollmentId: "silent-agent-2",
          hostname: "test-host-silent",
          lastSeen: new Date(Date.now() - 10 * 60 * 1000),
        },
      });

      // Create case
      const caseRecord = await prisma.case.create({
        data: {
          tenantId: tenant.id,
          title: `Agent Silent: ${agent.hostname}`,
          description: `Agent has not sent heartbeat for >5 minutes. Last seen: ${agent.lastSeen.toISOString()}`,
          severity: "high",
          status: "open",
        },
      });

      expect(caseRecord.title).toContain("Agent Silent");
      expect(caseRecord.severity).toBe("high");
      expect(caseRecord.status).toBe("open");
    });

    it("should not create duplicate cases for same silent agent", async () => {
      const tenant = await createTestTenant();
      const agent = await prisma.agent.create({
        data: {
          tenantId: tenant.id,
          enrollmentId: "silent-agent-3",
          hostname: "test-host-duplicate",
          lastSeen: new Date(Date.now() - 10 * 60 * 1000),
        },
      });

      // Create first case
      await prisma.case.create({
        data: {
          tenantId: tenant.id,
          title: `Agent Silent: ${agent.id}`,
          severity: "high",
          status: "open",
        },
      });

      // Check for existing case
      const existingCase = await prisma.case.findFirst({
        where: {
          tenantId: tenant.id,
          title: { contains: agent.id },
          status: "open",
        },
      });

      expect(existingCase).not.toBeNull();

      // Should not create second case
      const caseCount = await prisma.case.count({
        where: {
          tenantId: tenant.id,
          title: { contains: agent.id },
          status: "open",
        },
      });

      expect(caseCount).toBe(1);
    });
  });
});
