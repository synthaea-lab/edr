import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanDatabase, createTestAgent, createTestDetection, createTestTenant, prisma } from "../helpers/db";
import { runHunt } from "@/lib/hunt-runner";
import { makeChannel } from "../helpers/notify";

const HOUR = 3_600_000;
process.env.NOTIFY_CONSOLE_URL = "https://console.example.com";

const channel = (tenantId: string, huntIds: string[], events = ["hunt.new_matches"]) =>
  makeChannel(prisma, tenantId, { events, huntIds });
const mkHunt = (tenantId: string, name = "Encoded PowerShell") =>
  prisma.hunt.create({ data: { tenantId, ownerId: "u", name, query: { version: 1, lastHours: 24, techniques: ["T1059"] } } });

describe("hunt.new_matches", () => {
  beforeEach(cleanDatabase);
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("a run with new matches queues one message for a channel that lists the hunt, as a pointer", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001", timestamp: new Date(Date.now() - HOUR), event: { cmdline: "powershell -enc SECRET-ARGUMENT" } });
    const hunt = await mkHunt(tenant.id);
    const ch = await channel(tenant.id, [hunt.id]);
    const run = await runHunt(prisma, hunt, "schedule");
    expect(run.newMatchCount).toBe(1);

    const rows = await prisma.notification.findMany();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ channelId: ch.id, event: "hunt.new_matches", subject: hunt.id, seq: 1 });
    const p = rows[0].payload as { subject: { name: string; console_url: string | null }; change: { new_match_count: number; run_id: string } };
    expect(p.subject.name).toBe("Encoded PowerShell");
    expect(p.change).toMatchObject({ new_match_count: 1, run_id: run.id });
    expect(p.subject.console_url).toBe(`https://console.example.com/console/hunts/${hunt.id}`);
    // A webhook is a pointer to the console: no detection contents.
    expect(JSON.stringify(rows[0].payload)).not.toContain("SECRET-ARGUMENT");
  });

  it("a run with no new match queues nothing even for a subscribed channel", async () => {
    const tenant = await createTestTenant();
    const hunt = await mkHunt(tenant.id);
    await channel(tenant.id, [hunt.id]);
    expect((await runHunt(prisma, hunt, "schedule")).newMatchCount).toBe(0);
    expect(await prisma.notification.count()).toBe(0);
  });

  it("queues nothing when the channel does not list the hunt, or for another tenant", async () => {
    const tenant = await createTestTenant();
    const other = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const hunt = await mkHunt(tenant.id);
    const otherHunt = await mkHunt(tenant.id, "other");
    await channel(tenant.id, [otherHunt.id]); // lists a different hunt
    await channel(other.id, [hunt.id]); // another tenant's channel naming this hunt
    await runHunt(prisma, hunt, "manual"); // no detections: nothing new
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001", timestamp: new Date(Date.now() - HOUR) });
    await runHunt(prisma, hunt, "manual"); // a new match, but nobody subscribed
    expect(await prisma.notification.count()).toBe(0);
  });

  it("a second run inside the cooldown does not queue a second message", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const hunt = await mkHunt(tenant.id);
    await channel(tenant.id, [hunt.id]);
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001", timestamp: new Date(Date.now() - HOUR) });
    await runHunt(prisma, hunt, "schedule");
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001", timestamp: new Date() });
    await runHunt(prisma, hunt, "schedule");
    expect(await prisma.notification.count()).toBe(1);
  });

  it("a broken outbox never fails or duplicates the run", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const hunt = await mkHunt(tenant.id);
    await channel(tenant.id, [hunt.id]);
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001", timestamp: new Date(Date.now() - HOUR) });
    const spy = vi.spyOn(prisma.notificationChannel, "findMany").mockRejectedValueOnce(new Error("db down"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const run = await runHunt(prisma, hunt, "schedule");
    spy.mockRestore();
    log.mockRestore();
    expect(run.error).toBeNull();
    expect(run.newMatchCount).toBe(1);
    expect(await prisma.huntRun.count({ where: { huntId: hunt.id } })).toBe(1);
    expect(await prisma.notification.count()).toBe(0);
  });
});
