import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { PrismaClient } from "@prisma/client";
import { cleanDatabase, createTestTenant, createTestAgent } from "../helpers/db";
import { evaluateHostTransitions } from "@/lib/notify/host-transitions";
import { deliverDue } from "@/lib/notify/outbox";
import { sealSecret } from "@/lib/notify/secret";

const prisma = new PrismaClient();
const env = { NOTIFY_SECRET_KEY: "k1:" + "11".repeat(32), NOTIFY_CONSOLE_URL: "https://console.example.com/" };
const T0 = new Date("2026-10-19T10:00:00Z");
const at = (s: number) => new Date(T0.getTime() + s * 1000);
const ok = async () => ({ ok: true, statusCode: 204 });

async function channel(tenantId: string, events = ["host.degraded", "host.silent", "host.recovered"], over = {}) {
  const id = crypto.randomUUID();
  const sealed = sealSecret("whsec_x", id, env)!;
  return prisma.notificationChannel.create({
    data: { id, tenantId, url: "https://hooks.example.com/x", secretKeyId: sealed.keyId, secretSealed: sealed.sealed, events, createdBy: "u", ...over },
  });
}

async function setHealth(agentId: string, tenantId: string, over: { silentSensor?: boolean; lossObservedAt?: Date | null }) {
  const data = {
    tenantId, beaconAt: T0, receivedAt: T0, agentVersion: "0.1.0",
    spoolBytes: BigInt(0), spoolDropped: BigInt(0), enrichDropped: BigInt(0),
    lossObservedAt: over.lossObservedAt ?? null,
    sensors: [{ name: "linux-ebpf", pulse_count: 3, silent: over.silentSensor ?? false }],
  };
  await prisma.agentHealth.upsert({ where: { agentId }, create: { agentId, ...data }, update: data });
}
const rows = () => prisma.notification.findMany({ orderBy: [{ subject: "asc" }, { seq: "asc" }] });
const evalAt = (s: number) => evaluateHostTransitions(prisma, at(s), env);

describe("host transitions", () => {
  let tenantId: string;
  let agentId: string;
  beforeEach(async () => {
    await cleanDatabase();
    tenantId = (await createTestTenant()).id;
    agentId = (await createTestAgent(tenantId, "enr-1", { hostname: "web-01", lastSeen: at(0) })).id;
    await setHealth(agentId, tenantId, {});
  });
  afterAll(() => prisma.$disconnect());

  it("does nothing, and records nothing, while no channel subscribes", async () => {
    expect((await evalAt(1)).evaluated).toBe(0);
    expect((await prisma.agent.findUniqueOrThrow({ where: { id: agentId } })).notifiedStatus).toBeNull();
  });

  it("baselines on first sight: registering a channel does not announce a host already degraded", async () => {
    await setHealth(agentId, tenantId, { silentSensor: true });
    await channel(tenantId);
    const t = await evalAt(1);
    expect(t).toMatchObject({ evaluated: 1, baselined: 1, enqueued: 0 });
    expect((await prisma.agent.findUniqueOrThrow({ where: { id: agentId } })).notifiedStatus).toBe("degraded");
    expect(await rows()).toHaveLength(0);
    // Its next change is announced.
    await setHealth(agentId, tenantId, {});
    await evalAt(2);
    expect((await rows()).map((r) => r.event)).toEqual(["host.recovered"]);
  });

  it("one message when a host degrades, none while it stays degraded, one when it recovers", async () => {
    await channel(tenantId);
    await evalAt(1); // baseline healthy
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(2);
    await evalAt(3);
    await evalAt(4);
    let r = await rows();
    expect(r.map((x) => x.event)).toEqual(["host.degraded"]);
    const p = r[0].payload as { id: string; event: string; subject: { id: string; hostname: string; console_url: string }; change: { from: string; to: string; silent_sensors: string[] } };
    expect(p.id).toBe(r[0].id);
    expect(p.subject).toEqual({ id: agentId, hostname: "web-01", console_url: "https://console.example.com/console/ops" });
    expect(p.change).toMatchObject({ from: "healthy", to: "degraded", silent_sensors: ["linux-ebpf"] });
    // No detection content, command line or case text in a host payload.
    expect(JSON.stringify(p)).not.toMatch(/cmdline|command|description/i);

    await setHealth(agentId, tenantId, {});
    await evalAt(5);
    r = await rows();
    expect(r.map((x) => [x.event, x.seq])).toEqual([["host.degraded", 1], ["host.recovered", 2]]);
  });

  it("a loss stamp ends with the clock: recovered is announced when the window passes, with no beacon", async () => {
    await channel(tenantId);
    await evalAt(0);
    await setHealth(agentId, tenantId, { lossObservedAt: at(1) });
    await prisma.agent.update({ where: { id: agentId }, data: { lastSeen: at(700) } });
    await evalAt(2);
    expect((await rows()).map((r) => r.event)).toEqual(["host.degraded"]);
    await evalAt(700); // 10 min loss window over, host still beaconing
    expect((await rows()).map((r) => r.event)).toEqual(["host.degraded", "host.recovered"]);
  });

  it("a silent host carries the link to the case the silent-agent cron opened", async () => {
    await channel(tenantId);
    await evalAt(0);
    const c = await prisma.case.create({
      data: { tenantId, title: `Agent Silent: ${agentId}`, description: "x", severity: "high", status: "open" },
    });
    await evalAt(600); // lastSeen is at(0): more than 5 minutes ago
    const r = await rows();
    expect(r.map((x) => x.event)).toEqual(["host.silent"]);
    expect((r[0].payload as { change: { case_url: string } }).change.case_url).toBe(`https://console.example.com/console/cases/${c.id}`);
    // And it comes back healthy once it heartbeats again.
    await prisma.agent.update({ where: { id: agentId }, data: { lastSeen: at(610) } });
    await evalAt(611);
    expect((await rows()).map((x) => x.event)).toEqual(["host.silent", "host.recovered"]);
  });

  it("a flap inside the cooldown is held, not lost, and not repeated", async () => {
    await channel(tenantId);
    await evalAt(0);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(1);
    await deliverDue(prisma, at(2), { send: ok, env });
    await setHealth(agentId, tenantId, {});
    await evalAt(3); // recovered always goes
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(4); // degraded again, 3 s after the first was delivered: held
    expect((await rows()).map((x) => x.event)).toEqual(["host.degraded", "host.recovered"]);
    expect((await prisma.agent.findUniqueOrThrow({ where: { id: agentId } })).notifiedStatus).toBe("healthy");
    await prisma.agent.update({ where: { id: agentId }, data: { lastSeen: at(1890) } }); // still beaconing
    await evalAt(1900); // cooldown (30 min) over, still degraded: it goes
    expect((await rows()).map((x) => x.event)).toEqual(["host.degraded", "host.recovered", "host.degraded"]);
  });

  it("a held message is dropped when the host went back before the cooldown ended", async () => {
    await channel(tenantId);
    await evalAt(0);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(1);
    await deliverDue(prisma, at(2), { send: ok, env });
    await setHealth(agentId, tenantId, {});
    await evalAt(3);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(4); // held
    await setHealth(agentId, tenantId, {});
    await evalAt(5); // back to what was last told: nothing to send
    expect(await rows()).toHaveLength(2);
  });

  it("only the tenant's own channels receive its hosts", async () => {
    const other = (await createTestTenant()).id;
    const mine = await channel(tenantId);
    await channel(other);
    await evalAt(0);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(1);
    expect((await rows()).map((r) => r.channelId)).toEqual([mine.id]);
  });

  it("a channel that does not subscribe to a host event does not get it", async () => {
    await channel(tenantId, ["host.recovered"]);
    await evalAt(0);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(1);
    expect(await rows()).toHaveLength(0);
  });
});
