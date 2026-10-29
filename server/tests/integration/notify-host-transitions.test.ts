import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { PrismaClient } from "@prisma/client";
import { cleanDatabase, createTestTenant, createTestAgent } from "../helpers/db";
import { evaluateHostTransitions } from "@/lib/notify/host-transitions";
import { deliverDue } from "@/lib/notify/outbox";
import { GET as silentCron } from "@/app/api/cron/detect-silent-agents/route";
import { NextRequest } from "next/server";
import { makeChannel, NOTIFY_ENV } from "../helpers/notify";

const prisma = new PrismaClient();
const env = { ...NOTIFY_ENV, NOTIFY_CONSOLE_URL: "https://console.example.com/" };
const T0 = new Date("2026-10-19T10:00:00Z");
const at = (s: number) => new Date(T0.getTime() + s * 1000);
const ok = async () => ({ ok: true, statusCode: 204 });

const channel = (tenantId: string, events = ["host.degraded", "host.silent", "host.recovered"], over = {}) =>
  makeChannel(prisma, tenantId, { events, ...over });

const stateOf = async (channelId: string, subject: string) =>
  (await prisma.notificationState.findUnique({ where: { channelId_subject: { channelId, subject } } }))?.state ?? null;

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
    expect(await prisma.notificationState.count()).toBe(0);
  });

  it("baselines on first sight: registering a channel does not announce a host already degraded", async () => {
    await setHealth(agentId, tenantId, { silentSensor: true });
    const ch = await channel(tenantId);
    const t = await evalAt(1);
    expect(t).toMatchObject({ evaluated: 1, baselined: 1, enqueued: 0 });
    expect(await stateOf(ch.id, agentId)).toBe("degraded");
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

  it("a silent host carries the link to the case the silent-agent cron really opened, found by enrollment id", async () => {
    const ch = await channel(tenantId);
    await evalAt(0);
    // Another host's case must not be picked up, and the real cron titles a case by host name.
    const other = await createTestAgent(tenantId, "enr-2", { hostname: "db-02", lastSeen: at(0) });
    await prisma.agent.update({ where: { id: agentId }, data: { lastSeen: new Date(Date.now() - 10 * 60_000) } });
    await prisma.agent.update({ where: { id: other.id }, data: { lastSeen: new Date(Date.now() - 10 * 60_000) } });
    process.env.CRON_SECRET = "cron-test";
    const res = await silentCron(new NextRequest("http://localhost/api/cron/detect-silent-agents", { headers: { Authorization: "Bearer cron-test" } }));
    expect(res.status).toBe(200);
    const cases = await prisma.case.findMany({ where: { tenantId } });
    expect(cases.map((c) => c.title).sort()).toEqual(["Agent Silent: db-02", "Agent Silent: web-01"]);
    const mine = cases.find((c) => c.title === "Agent Silent: web-01")!;

    await evaluateHostTransitions(prisma, new Date(), env); // both hosts are silent now
    const r = (await rows()).filter((x) => x.subject === agentId);
    expect(r.map((x) => x.event)).toEqual(["host.silent"]);
    expect((r[0].payload as { change: { case_url: string } }).change.case_url).toBe(`https://console.example.com/console/cases/${mine.id}`);
    expect(ch.id).toBeTruthy();

    // And it comes back healthy once it heartbeats again.
    await prisma.agent.update({ where: { id: agentId }, data: { lastSeen: new Date() } });
    await evaluateHostTransitions(prisma, new Date(), env);
    expect((await rows()).filter((x) => x.subject === agentId).map((x) => x.event)).toEqual(["host.silent", "host.recovered"]);
  });

  it("without a configured console URL the links are null, never relative", async () => {
    await channel(tenantId);
    await evaluateHostTransitions(prisma, at(0), {});
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evaluateHostTransitions(prisma, at(1), {});
    const p = (await rows())[0].payload as { subject: { console_url: string | null } };
    expect(p.subject.console_url).toBeNull();
  });

  it("a flap inside the cooldown is held, not lost, and not repeated", async () => {
    const ch = await channel(tenantId);
    await evalAt(0);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(1);
    await deliverDue(prisma, at(2), { send: ok as never, env });
    await setHealth(agentId, tenantId, {});
    await evalAt(3); // recovered always goes
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(4); // degraded again, 3 s after the first was delivered: held
    expect((await rows()).map((x) => x.event)).toEqual(["host.degraded", "host.recovered"]);
    expect(await stateOf(ch.id, agentId)).toBe("healthy");
    await prisma.agent.update({ where: { id: agentId }, data: { lastSeen: at(1890) } }); // still beaconing
    await evalAt(1900); // cooldown (30 min) over, still degraded: it goes
    expect((await rows()).map((x) => x.event)).toEqual(["host.degraded", "host.recovered", "host.degraded"]);
  });

  it("a held message is dropped when the host went back before the cooldown ended", async () => {
    await channel(tenantId);
    await evalAt(0);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(1);
    await deliverDue(prisma, at(2), { send: ok as never, env });
    await setHealth(agentId, tenantId, {});
    await evalAt(3);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(4); // held
    await setHealth(agentId, tenantId, {});
    await evalAt(5); // back to what was last told: nothing to send
    expect(await rows()).toHaveLength(2);
  });

  it("a channel in its cooldown does not make another channel miss the transition (state is per channel)", async () => {
    const held = await channel(tenantId);
    await evalAt(0);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(1);
    await deliverDue(prisma, at(2), { send: ok as never, env });
    await setHealth(agentId, tenantId, {});
    await evalAt(3); // recovered goes to the first channel
    // A second channel registered now, then a new degradation within the first one's cooldown.
    const fresh = await channel(tenantId);
    await evalAt(4); // baselines `fresh` on a healthy host
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(5);
    const r = await rows();
    expect(r.filter((x) => x.channelId === held.id).map((x) => x.event)).toEqual(["host.degraded", "host.recovered"]);
    expect(r.filter((x) => x.channelId === fresh.id).map((x) => x.event)).toEqual(["host.degraded"]);
    expect(await stateOf(held.id, agentId)).toBe("healthy"); // held by its cooldown, not advanced
    expect(await stateOf(fresh.id, agentId)).toBe("degraded");
  });

  it("a channel registered later records the host without announcing it, and leaves the others alone", async () => {
    const first = await channel(tenantId);
    await evalAt(0);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(1);
    const late = await channel(tenantId);
    const t = await evalAt(2);
    expect(t.baselined).toBe(1);
    expect(await stateOf(late.id, agentId)).toBe("degraded");
    expect((await rows()).filter((x) => x.channelId === late.id)).toHaveLength(0);
    expect((await rows()).filter((x) => x.channelId === first.id)).toHaveLength(1);
  });

  it("a channel that does not subscribe to a change still advances, so it hears the next one", async () => {
    const ch = await channel(tenantId, ["host.silent", "host.recovered"]); // not host.degraded
    await evalAt(0);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(1); // degraded: nothing to tell this channel, state moves on
    expect(await stateOf(ch.id, agentId)).toBe("degraded");
    expect(await rows()).toHaveLength(0);
    await setHealth(agentId, tenantId, {});
    await evalAt(2);
    expect((await rows()).map((x) => x.event)).toEqual(["host.recovered"]);
  });

  it("a paused channel keeps being evaluated and queuing", async () => {
    const ch = await channel(tenantId, undefined, { status: "paused" });
    await evalAt(0);
    await setHealth(agentId, tenantId, { silentSensor: true });
    await evalAt(1);
    expect((await rows()).filter((x) => x.channelId === ch.id)).toHaveLength(1);
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
