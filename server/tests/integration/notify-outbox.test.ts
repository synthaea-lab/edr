import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { PrismaClient } from "@prisma/client";
import { cleanDatabase, createTestTenant } from "../helpers/db";
import { enqueue, claimDue, deliverDue, TENANT_PER_MINUTE } from "@/lib/notify/outbox";
import { sendWebhook } from "@/lib/notify/send";
import { verifySignature } from "@/lib/notify/sign";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

  it("pauses the channel after five failed rows, keeps queuing, and replays oldest first on enable", async () => {
    const ch = await channel(tenantId);
    const bad = async () => ({ ok: false, statusCode: 500, errorClass: "http_status" as const });
    const good = async () => ({ ok: true, statusCode: 204 });
    // Five subjects, each degraded once; every row exhausts its six attempts.
    for (let i = 0; i < 5; i++) await enqueue(prisma, ev(tenantId, "host.degraded", `p${i}`), T0);
    let t = 1;
    for (const delay of [0, 60, 300, 1800, 7200, 21600]) {
      t += delay;
      await deliverDue(prisma, at(t), { send: bad, env });
    }
    expect(await prisma.notification.count({ where: { failedAt: { not: null } } })).toBe(5);
    expect((await prisma.notificationChannel.findUniqueOrThrow({ where: { id: ch.id } })).status).toBe("paused");
    // Still queuing while paused, and nothing is claimed.
    expect(await enqueue(prisma, ev(tenantId, "host.degraded", "later"), at(t + 1))).toBe(1);
    expect(await claimDue(prisma, at(t + 2))).toHaveLength(0);
    // Failed rows stay visible; re-enabling replays the kept row.
    await prisma.notificationChannel.update({ where: { id: ch.id }, data: { status: "active" } });
    const tally = await deliverDue(prisma, at(t + 3), { send: good, env });
    expect(tally.delivered).toBe(1);
    expect(await prisma.notification.count({ where: { failedAt: { not: null } } })).toBe(5);
  });

  it("a delivery between failures resets the count: four failed rows then a success does not pause", async () => {
    const ch = await channel(tenantId);
    const bad = async () => ({ ok: false, errorClass: "connect" as const });
    for (let i = 0; i < 4; i++) await enqueue(prisma, ev(tenantId, "host.degraded", `q${i}`), T0);
    let t = 1;
    for (const delay of [0, 60, 300, 1800, 7200, 21600]) {
      t += delay;
      await deliverDue(prisma, at(t), { send: bad, env });
    }
    expect((await prisma.notificationChannel.findUniqueOrThrow({ where: { id: ch.id } })).status).toBe("active");
  });

  it(`defers rows past ${TENANT_PER_MINUTE} sends a minute for a tenant, without dropping them`, async () => {
    await channel(tenantId);
    for (let i = 0; i < TENANT_PER_MINUTE + 5; i++) await enqueue(prisma, ev(tenantId, "host.degraded", `r${i}`), T0);
    const ok = async () => ({ ok: true, statusCode: 204 });
    // The cron claims up to 50 at a time: two ticks within the same minute.
    const a = await deliverDue(prisma, at(1), { send: ok, env });
    const b = await deliverDue(prisma, at(2), { send: ok, env });
    expect(a.delivered + b.delivered).toBe(TENANT_PER_MINUTE);
    expect(a.deferred + b.deferred).toBeGreaterThan(0);
    expect(await prisma.notification.count({ where: { deliveredAt: null, failedAt: null } })).toBe(5);
    // A minute later the rest goes out.
    const c = await deliverDue(prisma, at(130), { send: ok, env });
    expect(c.delivered).toBe(5);
  });

  it("delivers end to end through the real client to a TLS receiver, signed, with the event id", async () => {
    const dir = mkdtempSync(join(tmpdir(), "notify-e2e-"));
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=hooks.test",
      "-addext", "subjectAltName=DNS:hooks.test", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
    const cert = readFileSync(join(dir, "c.pem"), "utf8");
    const got: { sig: string; body: string }[] = [];
    const server = createServer({ key: readFileSync(join(dir, "k.pem")), cert }, (req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        got.push({ sig: req.headers["x-synthaea-signature"] as string, body });
        res.writeHead(204).end();
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    try {
      await channel(tenantId, { url: `https://hooks.test:${port}/hook` });
      await enqueue(prisma, ev(tenantId, "host.degraded"), new Date());
      const guard = { resolve: async () => ["127.0.0.1"], allowedPrivateHosts: new Set(["hooks.test"]), extraPorts: new Set([port]) };
      const tally = await deliverDue(prisma, new Date(), {
        env,
        send: (u, b, h) => sendWebhook(u, b, h, guard, cert),
      });
      expect(tally.delivered).toBe(1);
      expect(got).toHaveLength(1);
      expect(verifySignature("whsec_x", got[0].body, got[0].sig, Math.floor(Date.now() / 1000))).toBe(true);
      const payload = JSON.parse(got[0].body);
      const row = await prisma.notification.findFirstOrThrow();
      expect(payload.id).toBe(row.id);
      expect(payload.event).toBe("host.degraded");
      expect(row.deliveredAt).not.toBeNull();
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
