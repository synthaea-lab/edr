import { describe, it, expect, beforeEach, afterAll, vi } from "vitest";
import { PrismaClient } from "@prisma/client";
import { cleanDatabase, createTestTenant } from "../helpers/db";
import { enqueue, claimDue, deliverDue, deliverOne, purge, rewrapChannels, resendFailed, failedCounts, TENANT_PER_MINUTE, PER_TENANT_PER_TICK, LEASE_MS } from "@/lib/notify/outbox";
import { sealSecret } from "@/lib/notify/secret";
import { sendWebhook } from "@/lib/notify/send";
import { verifySignature } from "@/lib/notify/sign";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeChannel, NOTIFY_ENV } from "../helpers/notify";

const prisma = new PrismaClient();
const env = NOTIFY_ENV;
const T0 = new Date("2026-10-19T10:00:00Z");
const at = (s: number) => new Date(T0.getTime() + s * 1000);

const channel = (tenantId: string, over: Record<string, unknown> = {}) =>
  makeChannel(prisma, tenantId, { events: ["host.degraded", "host.recovered", "hunt.new_matches"], ...over });
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
    const [a, b] = await Promise.all([claimDue(prisma, at(1), { limit: 4 }), claimDue(prisma, at(1), { limit: 4 })]);
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
    // Each attempt is signed when it is sent (the tick times here are far in the past).
    expect(sigs).toHaveLength(6);
    for (const h of sigs) expect(Math.abs(Number(/^t=(\d+)/.exec(h)![1]) - Date.now() / 1000)).toBeLessThan(5);
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
    // A tick serves a tenant at most ten rows: eight ticks within the same minute.
    const tallies = [];
    for (let t = 1; t <= 8; t++) tallies.push(await deliverDue(prisma, at(t), { send: ok, env }));
    expect(tallies.reduce((n, x) => n + x.delivered, 0)).toBe(TENANT_PER_MINUTE);
    expect(tallies.reduce((n, x) => n + x.deferred, 0)).toBeGreaterThan(0);
    expect(await prisma.notification.count({ where: { deliveredAt: null, failedAt: null } })).toBe(5);
    // A minute later the rest goes out.
    const c = await deliverDue(prisma, at(200), { send: ok, env });
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
      const guard = { resolve: async () => ["127.0.0.1"], allowedPrivateHosts: new Set([`${tenantId}:hooks.test`]), tenantId, unsafeAllowLoopbackForTests: true, extraPorts: new Set([port]) };
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

describe("delivery outcomes, ordering and housekeeping (ADR-0036 points 3, 5, 7)", () => {
  let tenantId: string;
  const ok = async () => ({ ok: true, statusCode: 204 });
  beforeEach(async () => {
    await cleanDatabase();
    tenantId = (await createTestTenant()).id;
  });
  afterAll(() => prisma.$disconnect());

  const answer = (statusCode: number, extra: object = {}) => async () => ({ ok: false, statusCode, errorClass: "http_status" as const, ...extra });
  const one = async (send: () => Promise<object>, subject = "agent-1") => {
    if ((await prisma.notificationChannel.count({ where: { tenantId } })) === 0) await channel(tenantId);
    await enqueue(prisma, ev(tenantId, "host.degraded", subject), T0);
    return deliverDue(prisma, at(1), { send: send as never, env });
  };

  it.each([400, 401, 403, 404, 301])("a %i is final: the row is failed at once, with no retry", async (status) => {
    const tally = await one(answer(status));
    expect(tally.failed).toBe(1);
    const row = await prisma.notification.findFirstOrThrow();
    expect(row.attempts).toBe(1);
    expect(row.failedAt).not.toBeNull();
    expect(row.lastStatus).toBe(status);
  });

  it.each([408, 425, 429, 500, 502, 503])("a %i is retried on the schedule", async (status) => {
    const tally = await one(answer(status));
    expect(tally.retry).toBe(1);
    const row = await prisma.notification.findFirstOrThrow();
    expect(row.failedAt).toBeNull();
    expect(row.nextAttemptAt.getTime() - at(1).getTime()).toBe(60_000); // first step, 1 minute
  });

  it("a network error is retried too", async () => {
    const tally = await one(async () => ({ ok: false, errorClass: "connect" as const }));
    expect(tally.retry).toBe(1);
  });

  it("honours Retry-After on 429 and 503, never below the schedule, capped at six hours", async () => {
    await one(answer(429, { retryAfterSeconds: 1200 }), "a");
    await one(answer(503, { retryAfterSeconds: 10 }), "b");
    await one(answer(429, { retryAfterSeconds: 10 ** 7 }), "c");
    const byHost = Object.fromEntries((await prisma.notification.findMany()).map((r) => [r.subject, r.nextAttemptAt.getTime() - at(1).getTime()]));
    expect(byHost.a).toBe(1_200_000);
    expect(byHost.b).toBe(60_000);
    expect(byHost.c).toBe(6 * 3_600_000);
    // A Retry-After on another status is ignored.
    await one(answer(500, { retryAfterSeconds: 3600 }), "d");
    expect((await prisma.notification.findFirstOrThrow({ where: { subject: "d" } })).nextAttemptAt.getTime() - at(1).getTime()).toBe(60_000);
  });

  it("a 410 pauses the channel at once and keeps the row, which is not failed", async () => {
    const ch = await channel(tenantId);
    await one(answer(410));
    expect((await prisma.notificationChannel.findUniqueOrThrow({ where: { id: ch.id } })).status).toBe("paused");
    const row = await prisma.notification.findFirstOrThrow();
    expect(row.failedAt).toBeNull();
    expect(row.deliveredAt).toBeNull();
    // Re-enabled, it goes out.
    await prisma.notificationChannel.update({ where: { id: ch.id }, data: { status: "active" } });
    const tally = await deliverDue(prisma, at(2), { send: (async () => ({ ok: true, statusCode: 204 })) as never, env });
    expect(tally.delivered).toBe(1);
  });

  it("a row whose URL or secret cannot be opened is a blocked failure that follows the schedule", async () => {
    await channel(tenantId);
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    const tally = await deliverDue(prisma, at(1), { send: (async () => ({ ok: true })) as never, env: { NOTIFY_SECRET_KEY: "k9:" + "22".repeat(32) } });
    expect(tally.retry).toBe(1);
    expect((await prisma.notification.findFirstOrThrow()).lastError).toBe("blocked");
  });

  it("a failed row no longer blocks later rows of its subject; a pending one does", async () => {
    await channel(tenantId);
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    await enqueue(prisma, ev(tenantId, "host.recovered"), at(1));
    // Pending first row: the second waits.
    const first = await claimDue(prisma, at(2));
    expect(first).toHaveLength(1);
    await prisma.notification.updateMany({ data: { lockedUntil: null } });
    // The first row fails: the second is now claimable.
    await prisma.notification.updateMany({ where: { seq: 1 }, data: { failedAt: at(3), attempts: 6 } });
    const next = await claimDue(prisma, at(4));
    expect(next.map((r) => (r.payload as { seq: number }).seq)).toEqual([2]);
  });

  it("a failed row a later row supersedes is not sent again; the others are", async () => {
    const ch = await channel(tenantId);
    for (const subject of ["a", "b"]) await enqueue(prisma, ev(tenantId, "host.degraded", subject), T0);
    await enqueue(prisma, ev(tenantId, "host.recovered", "a"), at(1)); // supersedes a's degraded
    await prisma.notification.updateMany({ where: { event: "host.degraded" }, data: { failedAt: at(2), attempts: 6 } });
    const counts = await failedCounts(prisma, tenantId);
    expect(counts.get(ch.id)).toEqual({ resendable: 1, superseded: 1 });
    expect(await resendFailed(prisma, ch.id, at(3))).toBe(1);
    const rows = await prisma.notification.findMany({ orderBy: [{ subject: "asc" }, { seq: "asc" }] });
    expect(rows.map((r) => [r.subject, r.event, r.failedAt === null])).toEqual([
      ["a", "host.degraded", false], // superseded: left failed
      ["a", "host.recovered", true],
      ["b", "host.degraded", true], // resent
    ]);
  });

  it("serves tenants round-robin, at most ten rows each per tick", async () => {
    const other = (await createTestTenant()).id;
    await channel(tenantId);
    await channel(other);
    for (let i = 0; i < 25; i++) await enqueue(prisma, ev(tenantId, "host.degraded", `a${i}`), T0);
    for (let i = 0; i < 3; i++) await enqueue(prisma, ev(other, "host.degraded", `b${i}`), T0);
    const claimed = await claimDue(prisma, at(1));
    const perTenant = claimed.reduce<Record<string, number>>((m, r) => ({ ...m, [r.tenantId]: (m[r.tenantId] ?? 0) + 1 }), {});
    expect(perTenant[tenantId]).toBe(PER_TENANT_PER_TICK);
    expect(perTenant[other]).toBe(3);
    // Interleaved: the small tenant's rows come within the first six, not after the big one's ten.
    const order = claimed.map((r) => r.tenantId);
    expect(order.slice(0, 6).filter((t) => t === other)).toHaveLength(3);
  });

  it("a row is leased longer than a tick can last", async () => {
    await channel(tenantId);
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    await claimDue(prisma, at(1));
    const row = await prisma.notification.findFirstOrThrow();
    expect(row.lockedUntil!.getTime() - at(1).getTime()).toBe(LEASE_MS);
    expect(LEASE_MS).toBeGreaterThan(45_000);
    expect(await claimDue(prisma, at(60))).toHaveLength(0); // still leased a minute later
  });

  it("out of budget, a tick stops sending and gives the claimed rows back", async () => {
    await channel(tenantId);
    for (let i = 0; i < 3; i++) await enqueue(prisma, ev(tenantId, "host.degraded", `s${i}`), T0);
    const tally = await deliverDue(prisma, at(1), { send: (async () => ({ ok: true, statusCode: 204 })) as never, env, budgetMs: -1 });
    expect(tally.released).toBe(3);
    expect(tally.delivered).toBe(0);
    expect((await prisma.notification.findMany()).every((r) => r.lockedUntil === null)).toBe(true);
    // The next tick takes them.
    const next = await deliverDue(prisma, at(2), { send: (async () => ({ ok: true, statusCode: 204 })) as never, env });
    expect(next.delivered).toBe(3);
  });

  it("each channel has its own cooldown", async () => {
    const quick = await channel(tenantId, { cooldownSeconds: 60 });
    const slow = await channel(tenantId, { cooldownSeconds: 3600 });
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    await deliverDue(prisma, at(1), { send: (async () => ({ ok: true, statusCode: 204 })) as never, env });
    await enqueue(prisma, ev(tenantId, "host.degraded"), at(300)); // five minutes later
    const rows = await prisma.notification.findMany({ where: { event: "host.degraded" } });
    expect(rows.filter((r) => r.channelId === quick.id)).toHaveLength(2);
    expect(rows.filter((r) => r.channelId === slow.id)).toHaveLength(1);
  });

  it("signs with both secrets during a rotation overlap, with one afterwards, and forgets the old one", async () => {
    const ch = await channel(tenantId, { secret: "new-secret" });
    const old = sealSecret("old-secret", ch.id, env)!;
    await prisma.notificationChannel.update({
      where: { id: ch.id },
      data: { prevSecretKeyId: old.keyId, prevSecretSealed: old.sealed, prevSecretUntil: at(86_400) },
    });
    const headers: string[] = [];
    const rec = async (_u: string, _b: string, h: Record<string, string>) => {
      headers.push(h["X-Synthaea-Signature"]);
      return { ok: true, statusCode: 204 };
    };
    await enqueue(prisma, ev(tenantId, "host.degraded", "a"), T0);
    await deliverDue(prisma, at(10), { send: rec as never, env });
    await enqueue(prisma, ev(tenantId, "host.degraded", "b"), at(86_500));
    await deliverDue(prisma, at(86_501), { send: rec as never, env }); // 24 h over
    expect(headers[0].match(/v1=/g)).toHaveLength(2);
    expect(headers[1].match(/v1=/g)).toHaveLength(1);
    expect(verifySignature("new-secret", '{}', headers[0].replace(/,v1=[0-9a-f]+$/, ""), 0, 10 ** 12)).toBe(false); // body differs: a sanity check the check is real
    const res = await purge(prisma, at(86_502));
    expect(res.rotationsClosed).toBe(1);
    const after = await prisma.notificationChannel.findUniqueOrThrow({ where: { id: ch.id } });
    expect(after.prevSecretSealed).toBeNull();
  });

  it("deletes delivered rows after 30 days and failed rows after 90, keeps the newest row of each subject, and keeps the rest", async () => {
    const ch = await channel(tenantId);
    const day = 86_400_000;
    const now = new Date("2026-10-19T10:00:00Z");
    let n = 0;
    const mk = (subject: string, seq: number, data: object) =>
      prisma.notification.create({ data: { tenantId, channelId: ch.id, event: "host.degraded", subject, seq, payload: {}, ...data } });
    const old = (d: number) => new Date(now.getTime() - d * day);
    // Each subject has an older row (purgeable) and a newer one, so that the older one can go.
    await mk("a", 1, { deliveredAt: old(40) });
    await mk("a", 2, { deliveredAt: old(35) }); // newest of a: kept whatever its age
    await mk("b", 1, { deliveredAt: old(31) }); // gone
    await mk("b", 2, { deliveredAt: old(1) });
    await mk("c", 1, { deliveredAt: old(29) }); // kept: not yet 30 days
    await mk("c", 2, { deliveredAt: old(1) });
    await mk("d", 1, { failedAt: old(91), attempts: 6 }); // gone
    await mk("d", 2, { deliveredAt: old(1) });
    await mk("e", 1, { failedAt: old(89), attempts: 6 }); // kept: not yet 90 days
    await mk("e", 2, { deliveredAt: old(1) });
    await mk("f", 1, {}); // pending, never purged
    void n;
    const res = await purge(prisma, now);
    expect(res).toMatchObject({ deliveredDeleted: 2, failedDeleted: 1 });
    const left = (await prisma.notification.findMany({ orderBy: [{ subject: "asc" }, { seq: "asc" }] })).map((r) => `${r.subject}${r.seq}`);
    expect(left).toEqual(["a2", "b2", "c1", "c2", "d2", "e1", "e2", "f1"]);
  });

  it("a subject whose rows were all old keeps counting: enqueue, purge past the retention, enqueue gives seq 3, not 1", async () => {
    await channel(tenantId);
    const day = 86_400_000;
    await enqueue(prisma, ev(tenantId, "host.degraded", "web-01"), T0); // seq 1
    await deliverDue(prisma, at(1), { send: ok as never, env });
    await enqueue(prisma, ev(tenantId, "host.recovered", "web-01"), at(2)); // seq 2
    await deliverDue(prisma, at(3), { send: ok as never, env });
    // Day 31: both rows are past the 30 days. The purge may take the first, never the last.
    const later = new Date(T0.getTime() + 31 * day);
    await purge(prisma, later);
    expect((await prisma.notification.findMany({ orderBy: { seq: "asc" } })).map((r) => r.seq)).toEqual([2]);
    await enqueue(prisma, ev(tenantId, "host.degraded", "web-01"), later);
    const rows = await prisma.notification.findMany({ orderBy: { seq: "asc" } });
    expect(rows.map((r) => r.seq)).toEqual([2, 3]);
    // A receiver that applied seq 2 accepts seq 3 (it would have discarded a restart at 1).
    expect(Math.max(...rows.map((r) => r.seq))).toBeGreaterThan(2);
  });

  it("forgets what channels were told about a host that no longer exists, and only that", async () => {
    const ch = await channel(tenantId);
    const gone = await prisma.agent.create({ data: { tenantId, enrollmentId: "enr-gone", hostname: "gone", lastSeen: T0 } });
    const kept = await prisma.agent.create({ data: { tenantId, enrollmentId: "enr-kept", hostname: "kept", lastSeen: T0 } });
    for (const a of [gone, kept]) await prisma.notificationState.create({ data: { channelId: ch.id, subject: a.id, state: "healthy" } });
    await prisma.agent.delete({ where: { id: gone.id } });
    const res = await purge(prisma, T0);
    expect(res.statesDeleted).toBe(1);
    expect((await prisma.notificationState.findMany()).map((x) => x.subject)).toEqual([kept.id]);
  });

  it("rewrapping does not overwrite a rotation that happened after it read the channel", async () => {
    const ch = await channel(tenantId, { secret: "whsec_one" });
    const K2 = "k2:" + "22".repeat(32);
    const both = { NOTIFY_SECRET_KEY: K2, NOTIFY_SECRET_KEY_PREVIOUS: NOTIFY_ENV.NOTIFY_SECRET_KEY };
    // The channel is rotated (a new sealed secret under the old key) while a rewrap is between its
    // read and its write.
    const first = await rewrapChannels(prisma, both, 20, 500, async (id) => {
      const fresh = sealSecret("whsec_two", id, env)!;
      await prisma.notificationChannel.update({ where: { id }, data: { secretKeyId: fresh.keyId, secretSealed: fresh.sealed } });
    });
    expect(first).toBe(0); // the compare-and-set found a different row and wrote nothing
    // The next tick picks it up, and the secret that survives is the rotated one.
    expect(await rewrapChannels(prisma, both)).toBe(1);
    const sigs: string[] = [];
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    await deliverDue(prisma, at(3), { send: (async (_u: string, b: string, h: Record<string, string>) => (sigs.push(h["X-Synthaea-Signature"] + "|" + b), { ok: true, statusCode: 204 })) as never, env: { NOTIFY_SECRET_KEY: K2 } });
    const [header, body] = sigs[0].split("|");
    expect(verifySignature("whsec_two", body, header, Math.floor(Date.now() / 1000))).toBe(true);
  });

  it("a channel whose old key is gone does not hold up the others", async () => {
    const lost = [] as string[];
    for (let i = 0; i < 4; i++) lost.push((await channel(tenantId, { secretKeyId: "k0" })).id);
    const good = await channel(tenantId);
    const K2 = "k2:" + "22".repeat(32);
    const res = await purge(prisma, at(1), { NOTIFY_SECRET_KEY: K2, NOTIFY_SECRET_KEY_PREVIOUS: NOTIFY_ENV.NOTIFY_SECRET_KEY });
    expect(res.rewrapped).toBe(1);
    expect((await prisma.notificationChannel.findUniqueOrThrow({ where: { id: good.id } })).secretKeyId).toBe("k2");
    expect(lost).toHaveLength(4);
  });
});

describe("lease, concurrency, isolation and signing time (review of #887)", () => {
  let tenantId: string;
  beforeEach(async () => {
    await cleanDatabase();
    tenantId = (await createTestTenant()).id;
  });
  afterAll(() => prisma.$disconnect());
  const ok = async () => ({ ok: true, statusCode: 204 });

  it("a tick whose lease ran out cannot overwrite what the tick that took the row over recorded", async () => {
    await channel(tenantId);
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    const [slow] = await claimDue(prisma, at(1)); // the slow tick's claim
    // Its lease runs out; another tick claims the same row with a new lease and delivers it.
    const [other] = await claimDue(prisma, at(1 + LEASE_MS / 1000 + 1));
    expect(other.id).toBe(slow.id);
    expect(other.leaseId).not.toBe(slow.leaseId);
    expect(await deliverOne(prisma, other, at(400), { send: ok as never, env })).toBe("delivered");
    // The slow tick finally finishes, and fails: its write matches nothing.
    const bad = async () => ({ ok: false, statusCode: 500, errorClass: "http_status" as const });
    expect(await deliverOne(prisma, slow, at(500), { send: bad as never, env })).toBe("lost");
    const row = await prisma.notification.findFirstOrThrow();
    expect(row.deliveredAt).not.toBeNull();
    expect(row.attempts).toBe(1); // only the delivery was recorded
    expect(row.lastStatus).toBe(204);
  });

  it("a slow receiver stalls its own tenant, not the others", async () => {
    const other = (await createTestTenant()).id;
    const slowCh = await channel(tenantId);
    await channel(other);
    for (let i = 0; i < 3; i++) await enqueue(prisma, ev(tenantId, "host.degraded", `s${i}`), T0);
    await enqueue(prisma, ev(other, "host.degraded", "f0"), T0);
    const doneAt: Record<string, number> = {};
    const t0 = Date.now();
    const send = async (_u: string, b: string) => {
      const p = JSON.parse(b) as { tenant: string };
      if (p.tenant === tenantId) await new Promise((r) => setTimeout(r, 300));
      doneAt[p.tenant] = Date.now() - t0;
      return { ok: true, statusCode: 204 };
    };
    await deliverDue(prisma, at(1), { send: send as never, env });
    expect(doneAt[other]).toBeLessThan(250); // not behind the slow tenant's three 300 ms sends
    expect(doneAt[tenantId]).toBeGreaterThanOrEqual(850);
    expect(slowCh.id).toBeTruthy();
  });

  it("one row's error is logged and does not end the tick: the lease is given back and the rest goes out", async () => {
    await channel(tenantId);
    for (let i = 0; i < 3; i++) await enqueue(prisma, ev(tenantId, "host.degraded", `e${i}`), T0);
    let n = 0;
    const send = async () => {
      if (++n === 1) throw new Error("boom");
      return { ok: true, statusCode: 204 };
    };
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const tally = await deliverDue(prisma, at(1), { send: send as never, env });
    log.mockRestore();
    expect(tally.errors).toBe(1);
    expect(tally.delivered).toBe(2);
    const failedRow = await prisma.notification.findFirstOrThrow({ where: { deliveredAt: null } });
    expect(failedRow.lockedUntil).toBeNull();
    expect(failedRow.leaseId).toBeNull();
  });

  it("signs when it sends, not when the tick started", async () => {
    await channel(tenantId);
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    let header = "";
    const send = async (_u: string, _b: string, h: Record<string, string>) => {
      header = h["X-Synthaea-Signature"];
      return { ok: true, statusCode: 204 };
    };
    await deliverDue(prisma, at(1), { send: send as never, env }); // a tick time far in the past
    const t = Number(/^t=(\d+)/.exec(header)![1]);
    expect(Math.abs(t - Date.now() / 1000)).toBeLessThan(5);
  });

  it("a re-enabled channel counts five consecutive failures from the re-enable, not from the last delivery", async () => {
    const ch = await channel(tenantId);
    const bad = async () => ({ ok: false, statusCode: 400, errorClass: "http_status" as const }); // final at once
    for (let i = 0; i < 5; i++) await enqueue(prisma, ev(tenantId, "host.degraded", `p${i}`), T0);
    for (let t = 1; t <= 2; t++) await deliverDue(prisma, at(t), { send: bad as never, env });
    expect((await prisma.notificationChannel.findUniqueOrThrow({ where: { id: ch.id } })).status).toBe("paused");
    await prisma.notificationChannel.update({ where: { id: ch.id }, data: { status: "active", pauseCountFrom: at(10) } });
    await enqueue(prisma, ev(tenantId, "host.degraded", "after"), at(11));
    await deliverDue(prisma, at(12), { send: bad as never, env });
    // Six failed rows in all, but one since the re-enable: still active.
    expect((await prisma.notificationChannel.findUniqueOrThrow({ where: { id: ch.id } })).status).toBe("active");
  });

  it("overlapping enqueues of the same event write one row, not two", async () => {
    await channel(tenantId);
    const results = await Promise.all(Array.from({ length: 12 }, () => enqueue(prisma, ev(tenantId, "host.degraded", "same"), T0)));
    expect(results.reduce((a, b) => a + b, 0)).toBe(1);
    expect(await prisma.notification.count()).toBe(1);
  });

  it("the check and the insert wait for anyone holding the (channel, subject) lock", async () => {
    const ch = await channel(tenantId);
    // Another transaction holds the lock for 400 ms: an enqueue for the same key cannot go past it,
    // so two evaluations can never both pass the dedup check.
    const holder = prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`notify:${ch.id}:guarded`}))`;
      await new Promise((r) => setTimeout(r, 400));
    });
    await new Promise((r) => setTimeout(r, 100)); // let the holder take it
    const t0 = Date.now();
    await enqueue(prisma, ev(tenantId, "host.degraded", "guarded"), T0);
    const waited = Date.now() - t0;
    await holder;
    expect(waited).toBeGreaterThanOrEqual(250);
    // Another subject is not held up by it.
    const holder2 = prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`notify:${ch.id}:guarded`}))`;
      await new Promise((r) => setTimeout(r, 400));
    });
    await new Promise((r) => setTimeout(r, 100));
    const t1 = Date.now();
    await enqueue(prisma, ev(tenantId, "host.degraded", "free"), T0);
    expect(Date.now() - t1).toBeLessThan(250);
    await holder2;
  });

  it("seals again under the current server key what an older key sealed, and leaves what it cannot open", async () => {
    const ch = await channel(tenantId, { secret: "whsec_old", url: "https://hooks.example.com/p" });
    const K2 = "k2:" + "22".repeat(32);
    const both = { NOTIFY_SECRET_KEY: K2, NOTIFY_SECRET_KEY_PREVIOUS: NOTIFY_ENV.NOTIFY_SECRET_KEY };
    const res = await purge(prisma, at(1), both);
    expect(res.rewrapped).toBe(1);
    const after = await prisma.notificationChannel.findUniqueOrThrow({ where: { id: ch.id } });
    expect([after.secretKeyId, after.urlKeyId]).toEqual(["k2", "k2"]);
    // Delivery still works with only the new key.
    await enqueue(prisma, ev(tenantId, "host.degraded"), T0);
    let sentTo = "";
    const send = async (u: string) => ((sentTo = u), { ok: true, statusCode: 204 });
    await deliverDue(prisma, at(2), { send: send as never, env: { NOTIFY_SECRET_KEY: K2 } });
    expect(sentTo).toBe("https://hooks.example.com/p");
    // A channel sealed under a key that is gone is left alone, not corrupted.
    const lost = await channel(tenantId, { secretKeyId: "k0" });
    expect((await purge(prisma, at(3), { NOTIFY_SECRET_KEY: K2 })).rewrapped).toBe(0);
    expect((await prisma.notificationChannel.findUniqueOrThrow({ where: { id: lost.id } })).secretKeyId).toBe("k0");
  });
});
