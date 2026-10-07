import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { createMtlsHeaders } from "../helpers/http";
import { POST as register } from "@/app/api/ingest/decoy/route";
import { GET as cronSilentAgents } from "@/app/api/cron/detect-silent-agents/route";
import {
  DECOY_ALARM_COOLDOWN_MS,
  MAX_DECOY_TOKENS_PER_AGENT,
  flushDecoyReports,
  hashToken,
} from "@/lib/decoy";

/**
 * Decoy credentials (issue #81) through the real routes and database: an agent registers the
 * hashes of its decoy tokens, and a request that presents one raises an alarm naming the host
 * it was planted on.
 */
const SECRET = "test-proxy-secret";
const TOKEN = "syn_dk_0123456789abcdef0123456789abcdef";

function registration(enrollmentId: string, tokens: string[]) {
  return new NextRequest("http://localhost/api/ingest/decoy", {
    method: "POST",
    headers: { ...createMtlsHeaders(enrollmentId), "X-Proxy-Secret": SECRET },
    body: JSON.stringify({ tokens }),
  });
}

function cron(authorization: string, extra: Record<string, string> = {}) {
  return new NextRequest("http://localhost/api/cron/detect-silent-agents", {
    headers: { Authorization: authorization, ...extra },
  });
}

/** A presentation of `header`, with the alarm (recorded after the answer) allowed to finish. */
async function present(header: string, extra: Record<string, string> = {}) {
  const res = await cronSilentAgents(cron(header, extra));
  await flushDecoyReports();
  return res;
}

const alarms = (agentId: string) =>
  prisma.detection.findMany({ where: { agentId, technique: "T1552.001" } });

describe("decoy tokens (real database)", () => {
  beforeEach(async () => {
    process.env.NGINX_PROXY_SECRET = SECRET;
    await cleanDatabase();
  });
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("registers hashes idempotently and stores no token", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const hash = hashToken(TOKEN);

    const first = await register(registration(agent.enrollmentId, [hash]));
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ registered: 1, conflicts: 0 });
    const again = await register(registration(agent.enrollmentId, [hash, hash]));
    expect(await again.json()).toMatchObject({ registered: 1, conflicts: 0 });

    const rows = await prisma.decoyToken.findMany({ where: { agentId: agent.id } });
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain(TOKEN);
  });

  it("requires the proxy secret and an enrolled agent", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const noSecret = new NextRequest("http://localhost/api/ingest/decoy", {
      method: "POST",
      headers: createMtlsHeaders(agent.enrollmentId),
      body: JSON.stringify({ tokens: [] }),
    });
    expect((await register(noSecret)).status).toBe(403);
    expect((await register(registration("nobody-enrolled", []))).status).toBe(403);
  });

  it("rejects a malformed registration, including a raw token", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    expect((await register(registration(agent.enrollmentId, [TOKEN]))).status).toBe(400);
    expect(await prisma.decoyToken.count()).toBe(0);
  });

  it("does not let another agent take a hash that is already registered", async () => {
    const tenant = await createTestTenant();
    const first = await createTestAgent(tenant.id);
    const second = await createTestAgent(tenant.id);
    const hash = hashToken(TOKEN);
    await register(registration(first.enrollmentId, [hash]));

    const res = await register(registration(second.enrollmentId, [hash]));
    expect(await res.json()).toMatchObject({ registered: 0, conflicts: 1 });
    expect((await prisma.decoyToken.findUniqueOrThrow({ where: { tokenSha256: hash } })).agentId).toBe(first.id);
  });

  it("bounds the hashes one agent may hold", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const hashes = (from: number, n: number) =>
      Array.from({ length: n }, (_, i) => hashToken(`syn_dk_${from + i}`));
    expect((await register(registration(agent.enrollmentId, hashes(0, MAX_DECOY_TOKENS_PER_AGENT)))).status).toBe(200);
    expect((await register(registration(agent.enrollmentId, hashes(10_000, 1)))).status).toBe(409);
    // Re-sending what it already holds is still fine.
    expect((await register(registration(agent.enrollmentId, hashes(0, 5)))).status).toBe(200);
  });

  it("raises a high alarm naming the planting host when a decoy is presented, and still answers 401", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id, undefined, { hostname: "web-01" });
    await register(registration(agent.enrollmentId, [hashToken(TOKEN)]));

    const res = await present(`Bearer ${TOKEN}`, {
      "x-real-ip": "203.0.113.9",
      "x-forwarded-for": "198.51.100.77, 203.0.113.9",
      "user-agent": "curl/8",
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Unauthorized" });

    const found = await alarms(agent.id);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ severity: "high", tenantId: tenant.id });
    expect(found[0].meta).toMatchObject({
      source: "deception",
      planting_host: "web-01",
      client_address: "203.0.113.9",
      user_agent: "curl/8",
    });
    expect(JSON.stringify(found[0])).not.toContain(TOKEN);
  });

  it("raises one alarm per decoy per cooldown, not one per request", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await register(registration(agent.enrollmentId, [hashToken(TOKEN)]));
    for (let i = 0; i < 3; i++) await present(`Bearer ${TOKEN}`);
    expect(await alarms(agent.id)).toHaveLength(1);

    // Past the cooldown it alarms again.
    await prisma.detection.updateMany({
      where: { agentId: agent.id },
      data: { timestamp: new Date(Date.now() - DECOY_ALARM_COOLDOWN_MS - 1_000) },
    });
    await present(`Bearer ${TOKEN}`);
    expect(await alarms(agent.id)).toHaveLength(2);
  });

  it("raises no alarm for a bearer that is not a registered decoy", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await register(registration(agent.enrollmentId, [hashToken(TOKEN)]));
    for (const header of [
      "Bearer nope",
      "Bearer syn_dk_not_registered",
      `Basic ${TOKEN}`,
      "Bearer ",
    ]) {
      expect((await present(header)).status).toBe(401);
    }
    expect(await alarms(agent.id)).toHaveLength(0);
  });

  it("does not alarm on the real cron secret", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await register(registration(agent.enrollmentId, [hashToken(TOKEN)]));
    const res = await present(`Bearer ${process.env.CRON_SECRET}`);
    expect(res.status).not.toBe(401);
    expect(await alarms(agent.id)).toHaveLength(0);
  });

  it("records one alarm when the same decoy is presented many times at once", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await register(registration(agent.enrollmentId, [hashToken(TOKEN)]));
    await Promise.all(Array.from({ length: 8 }, () => cronSilentAgents(cron(`Bearer ${TOKEN}`))));
    await flushDecoyReports();
    expect(await alarms(agent.id)).toHaveLength(1);
  });

  it("takes the address from X-Real-IP, never from the first X-Forwarded-For hop", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await register(registration(agent.enrollmentId, [hashToken(TOKEN)]));
    // No X-Real-IP: nginx appended the connection's address last, the client wrote the rest.
    await present(`Bearer ${TOKEN}`, { "x-forwarded-for": "10.0.0.1, 192.0.2.50" });
    const [alarm] = await alarms(agent.id);
    expect((alarm.meta as { client_address?: string }).client_address).toBe("192.0.2.50");
  });
});
