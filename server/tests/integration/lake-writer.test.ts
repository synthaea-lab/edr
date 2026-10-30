import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { parquetReadObjects } from "hyparquet";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { createMtlsHeaders } from "../helpers/http";
import { FsLakeStore } from "@/lib/lake-store";
import { drainLakeQueue, enqueueLakeBatch } from "@/lib/lake-writer";
import { POST as ingest } from "@/app/api/v1/ingest/events/route";
import { GET as writeLake } from "@/app/api/cron/write-lake/route";

const SECRET = "test-proxy-secret";
const AT = new Date(Date.UTC(2026, 9, 29, 10, 0, 0));
const exec = (over: Record<string, unknown> = {}) => ({
  type: "exec",
  meta: { comm: "bash", timestamp_ns: AT.getTime() * 1_000_000 },
  image_path: "/usr/bin/curl",
  sha256: "b".repeat(64),
  ...over,
});

let dir: string;

beforeEach(async () => {
  await cleanDatabase();
  dir = await mkdtemp(path.join(os.tmpdir(), "lake-int-"));
  process.env.NGINX_PROXY_SECRET = SECRET;
  process.env.CRON_SECRET = "test_cron_secret";
  process.env.LAKE_DIR = dir;
});

afterEach(async () => {
  delete process.env.LAKE_DIR;
  await rm(dir, { recursive: true, force: true });
});

afterAll(async () => {
  await cleanDatabase();
  await prisma.$disconnect();
});

async function filesUnder(root: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true, recursive: true })) {
    if (entry.isFile()) out.push(path.relative(root, path.join(entry.parentPath, entry.name)));
  }
  return out.sort();
}

async function rowsOf(file: string): Promise<Record<string, unknown>[]> {
  const bytes = await readFile(path.join(dir, file));
  const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  return (await parquetReadObjects({ file: buf })) as Record<string, unknown>[];
}

describe("telemetry lake writer against Postgres", () => {
  it("takes an agent's upload from the ingest route to a Parquet file the tenant owns", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id, "agent-lake-1");
    const res = await ingest(
      new NextRequest("http://localhost/api/v1/ingest/events", {
        method: "POST",
        headers: { ...createMtlsHeaders("agent-lake-1"), "X-Proxy-Secret": SECRET },
        body: JSON.stringify({ agent_id: null, events: [exec(), exec({ image_path: "/bin/ls" }), { type: "dns_query", query: "example.com", meta: { timestamp_ns: AT.getTime() * 1_000_000 } }] }),
      })
    );
    expect(res.status).toBe(200);
    expect(await prisma.lakeBatch.count()).toBe(1);

    const cron = await writeLake(new NextRequest("http://localhost/api/cron/write-lake", { headers: { Authorization: "Bearer test_cron_secret" } }));
    expect(cron.status).toBe(200);
    expect(await cron.json()).toMatchObject({ batches: 1, events: 3, files: 2, remaining: 0 });
    expect(await prisma.lakeBatch.count()).toBe(0);

    const files = await filesUnder(dir);
    expect(files).toHaveLength(2);
    expect(files.every((f) => f.startsWith(`tenant=${tenant.id}/date=`))).toBe(true);
    const execFile = files.find((f) => f.includes("/type=exec/"))!;
    const rows = await rowsOf(execFile);
    expect(rows.map((r) => r.image_path).sort()).toEqual(["/bin/ls", "/usr/bin/curl"]);
    expect(rows.every((r) => r.agent_id === agent.id && r.comm === "bash")).toBe(true);
    expect(JSON.parse(rows[0].event as string).type).toBe("exec");
  });

  it("keeps each tenant's events in its own prefix", async () => {
    const [t1, t2] = [await createTestTenant(), await createTestTenant()];
    const [a1, a2] = [await createTestAgent(t1.id), await createTestAgent(t2.id)];
    await enqueueLakeBatch(prisma, { tenantId: t1.id, agentId: a1.id, events: [exec({ image_path: "/only/t1" })], receivedAt: AT });
    await enqueueLakeBatch(prisma, { tenantId: t2.id, agentId: a2.id, events: [exec({ image_path: "/only/t2" })], receivedAt: AT });
    await drainLakeQueue(prisma, new FsLakeStore(dir), { now: AT });
    for (const file of await filesUnder(dir)) {
      const owner = file.startsWith(`tenant=${t1.id}/`) ? "/only/t1" : "/only/t2";
      expect((await rowsOf(file)).map((r) => r.image_path)).toEqual([owner]);
    }
  });

  it("writes nothing for a tenant that keeps nothing, and still empties its queue", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await prisma.tenant.update({ where: { id: tenant.id }, data: { lakeRetentionDays: 0 } });
    await enqueueLakeBatch(prisma, { tenantId: tenant.id, agentId: agent.id, events: [exec()], receivedAt: AT });
    expect(await drainLakeQueue(prisma, new FsLakeStore(dir), { now: AT })).toMatchObject({ events: 0, files: 0, droppedNoRetention: 1, remaining: 0 });
    expect(await filesUnder(dir)).toEqual([]);
    expect(await prisma.lakeBatch.count()).toBe(0);
  });

  it("leaves the queue intact when the store fails, and a later drain writes it", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await enqueueLakeBatch(prisma, { tenantId: tenant.id, agentId: agent.id, events: [exec()], receivedAt: AT });
    await expect(drainLakeQueue(prisma, { put: async () => { throw new Error("disk full"); } }, { now: AT })).rejects.toThrow("disk full");
    expect(await prisma.lakeBatch.count()).toBe(1);
    expect(await drainLakeQueue(prisma, new FsLakeStore(dir), { now: AT })).toMatchObject({ batches: 1, files: 1, remaining: 0 });
  });

  it("takes at most maxBatches, oldest first, and reports what remains", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    for (let i = 0; i < 3; i++) {
      await enqueueLakeBatch(prisma, { tenantId: tenant.id, agentId: agent.id, events: [exec({ image_path: `/b/${i}` })], receivedAt: new Date(AT.getTime() + i * 1000) });
    }
    expect(await drainLakeQueue(prisma, new FsLakeStore(dir), { maxBatches: 2, now: AT })).toMatchObject({ batches: 2, events: 2, remaining: 1 });
    const left = await prisma.lakeBatch.findMany();
    expect(left).toHaveLength(1);
    expect((left[0].events as { image_path: string }[])[0].image_path).toBe("/b/2");
  });

  it("two drains at once do not take the same batch", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    for (let i = 0; i < 6; i++) {
      await enqueueLakeBatch(prisma, { tenantId: tenant.id, agentId: agent.id, events: [exec({ image_path: `/p/${i}` })], receivedAt: new Date(AT.getTime() + i * 1000) });
    }
    const store = new FsLakeStore(dir);
    const [a, b] = await Promise.all([drainLakeQueue(prisma, store, { maxBatches: 3, now: AT }), drainLakeQueue(prisma, store, { maxBatches: 3, now: AT })]);
    expect(a.batches + b.batches).toBe(6);
    const seen: string[] = [];
    for (const file of await filesUnder(dir)) seen.push(...(await rowsOf(file)).map((r) => r.image_path as string));
    expect(seen.sort()).toEqual(["/p/0", "/p/1", "/p/2", "/p/3", "/p/4", "/p/5"]);
    expect(await prisma.lakeBatch.count()).toBe(0);
  });

  it("deletes a tenant's queue with the tenant", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await enqueueLakeBatch(prisma, { tenantId: tenant.id, agentId: agent.id, events: [exec()], receivedAt: AT });
    await prisma.tenant.delete({ where: { id: tenant.id } }).catch(async () => {
      await prisma.agent.deleteMany({ where: { tenantId: tenant.id } });
      await prisma.tenant.delete({ where: { id: tenant.id } });
    });
    expect(await prisma.lakeBatch.count()).toBe(0);
  });
});
