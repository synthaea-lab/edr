import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { PrismaClient } from "@prisma/client";
import { cleanDatabase, createTestTenant } from "../helpers/db";
import { enqueue, claimDue, deliverDue } from "@/lib/notify/outbox";
import { sealSecret } from "@/lib/notify/secret";

const prisma = new PrismaClient();
const KEY = "k1:" + "11".repeat(32);
const env = { NOTIFY_SECRET_KEY: KEY };
const T0 = new Date("2026-10-19T10:00:00Z");
const at = (s: number) => new Date(T0.getTime() + s * 1000);

async function channel(tenantId: string, over: Record<string, unknown> = {}) {
  const id = crypto.randomUUID();
  const sealed = sealSecret("whsec_x", id, env)!;
  return prisma.notificationChannel.create({
    data: {
      id, tenantId, url: "https://hooks.example.com/x", secretKeyId: sealed.keyId, secretSealed: sealed.sealed,
      events: ["host.degraded", "host.recovered", "hunt.new_matches"], createdBy: "u", ...over,
    },
  });
}
const ev = (tenantId: string, event: "host.degraded" | "host.recovered", subject = "agent-1") =>
  ({ tenantId, event, subject, data: { subject: { id: subject } } });

describe("notification outbox", () => {
  let tenantId: string;
  beforeEach(async () => {
    await cleanDatabase();
    tenantId = (await createTestTenant()).id;
  });
  afterAll(() => prisma.$disconnect());

  it("dedups an undelivered duplicate and numbers rows per subject", async () => {
    await channel(tenantId);
    expect(await enqueue(prisma, ev(tenantId, "host.degraded"), T0)).toBe(1);
    expect(await enqueue(prisma, ev(tenantId, "host.degraded"), at(5))).toBe(0);
    expect(await enqueue(prisma, ev(tenantId, "host.recovered"), at(10))).toBe(1);
    const rows = await prisma.notification.findMany({ orderBy: { seq: "asc" } });
    expect(rows.map((r) => [r.event, r.seq])).toEqual([["host.degraded", 1], ["host.recovered", 2]]);
  });

  it("a recovered row waits behind an earlier undelivered row of the same subject", async () => {
    await channel(tenantId);
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    await enqueue(prisma, ev(tenantId, "host.recovered"), at(1));
    const first = await claimDue(prisma, at(2));
    expect(first).toHaveLength(1);
    expect((first[0].payload as { event: string }).event).toBe("host.degraded");
    // Still leased and undelivered: the recovered row is not claimable.
    expect(await claimDue(prisma, at(3))).toHaveLength(0);
  });

  it("two claimers never take the same row", async () => {
    await channel(tenantId);
    for (let i = 0; i < 6; i++) await enqueue(prisma, ev(tenantId, "host.degraded", `a${i}`), T0);
    const [a, b] = await Promise.all([claimDue(prisma, at(1), 4), claimDue(prisma, at(1), 4)]);
    const ids = [...a, ...b].map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toHaveLength(6);
  });

  it("delivers with a fresh signature per attempt, retries with backoff, then pauses after five failed rows", async () => {
    const ch = await channel(tenantId);
    const sigs: string[] = [];
    const bad = async (_u: string, _b: string, h: Record<string, string>) => {
      sigs.push(h["X-Synthaea-Signature"]);
      return { ok: false, statusCode: 500, errorClass: "http_status" as const };
    };
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    // Attempt n is due after the delay of attempt n-1: 1, 5, 30 minutes, 2 and 6 hours.
    let t = 1;
    for (const delay of [0, 60, 300, 1800, 7200, 21600]) {
      t += delay;
      await deliverDue(prisma, at(t), { send: bad, env });
    }
    const row = await prisma.notification.findFirstOrThrow();
    expect(row.attempts).toBe(6);
    expect(row.failedAt).not.toBeNull();
    expect(new Set(sigs).size).toBe(sigs.length); // t differs per attempt
    expect((await prisma.notificationChannel.findUniqueOrThrow({ where: { id: ch.id } })).lastError).toBe("http_status");
  });

  it("marks a delivery and keeps no response body", async () => {
    const ch = await channel(tenantId);
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    const ok = async () => ({ ok: true, statusCode: 204 });
    const tally = await deliverDue(prisma, at(1), { send: ok, env });
    expect(tally.delivered).toBe(1);
    const c = await prisma.notificationChannel.findUniqueOrThrow({ where: { id: ch.id } });
    expect(c.lastStatusCode).toBe(204);
    // Within the cooldown the same degraded is not queued again, after it it is.
    expect(await enqueue(prisma, ev(tenantId, "host.degraded"), at(600))).toBe(0);
    expect(await enqueue(prisma, ev(tenantId, "host.degraded"), at(1900))).toBe(1);
  });

  it("does not claim a paused channel's rows, but keeps queuing for it", async () => {
    await channel(tenantId, { status: "paused" });
    expect(await enqueue(prisma, ev(tenantId, "host.degraded"), T0)).toBe(1);
    expect(await claimDue(prisma, at(1))).toHaveLength(0);
  });

  it("hunt.new_matches only reaches a channel that lists the hunt", async () => {
    await channel(tenantId, { huntIds: ["h1"] });
    const e = (subject: string) => ({ tenantId, event: "hunt.new_matches" as const, subject, data: {} });
    expect(await enqueue(prisma, e("h2"), T0)).toBe(0);
    expect(await enqueue(prisma, e("h1"), T0)).toBe(1);
  });
});
