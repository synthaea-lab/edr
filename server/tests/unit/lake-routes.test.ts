import { mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const db = vi.hoisted(() => ({
  agent: { findUnique: vi.fn(), update: vi.fn() },
  agentHealth: { findUnique: vi.fn(), upsert: vi.fn() },
  lakeBatch: { create: vi.fn(), findMany: vi.fn(), deleteMany: vi.fn(), count: vi.fn() },
  tenant: { findMany: vi.fn() },
  $executeRaw: vi.fn(),
  $queryRaw: vi.fn(),
  $transaction: vi.fn(),
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { POST as ingestEvents } from "@/app/api/ingest/events/route";
import { GET as writeLake } from "@/app/api/cron/write-lake/route";

const SECRET = "test-proxy-secret";
const NOW = Date.UTC(2026, 9, 29, 10, 0, 0);
const AGENT_HEADERS = {
  "X-Proxy-Secret": SECRET,
  "X-Client-Cert-Verified": "SUCCESS",
  "X-Client-Cert-Subject": "CN=agent-1,O=synthaea",
  "Content-Type": "application/json",
};
const exec = (over: Record<string, unknown> = {}) => ({
  type: "exec",
  meta: { comm: "bash", timestamp_ns: NOW * 1_000_000 },
  image_path: "/usr/bin/curl",
  ...over,
});

const postEvents = (body: unknown) =>
  ingestEvents(new NextRequest("http://localhost/api/ingest/events", { method: "POST", headers: AGENT_HEADERS, body: JSON.stringify(body) }));

let lakeDir: string;

beforeEach(async () => {
  vi.clearAllMocks();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  lakeDir = await mkdtemp(path.join(os.tmpdir(), "lake-route-"));
  process.env.NGINX_PROXY_SECRET = SECRET;
  process.env.CRON_SECRET = "cron-secret";
  delete process.env.LAKE_DIR;
  delete process.env.LAKE_WRITER_MAX_BATCHES;
  db.agent.findUnique.mockResolvedValue({ id: "a1", tenantId: "t1", ring: "prod" });
  db.agent.update.mockResolvedValue({});
  db.$executeRaw.mockResolvedValue(1);
  db.lakeBatch.create.mockResolvedValue({});
});

afterEach(async () => {
  vi.useRealTimers();
  await rm(lakeDir, { recursive: true, force: true });
});

describe("POST /api/ingest/events and the lake queue", () => {
  it("queues nothing while the lake is off", async () => {
    expect((await postEvents({ events: [exec()] })).status).toBe(200);
    expect(db.lakeBatch.create).not.toHaveBeenCalled();
  });

  it("queues the accepted events of the batch for the agent's tenant, and not the malformed ones", async () => {
    process.env.LAKE_DIR = lakeDir;
    const res = await postEvents({ events: [exec(), 7, { nope: true }, exec({ image_path: "/bin/ls" })] });
    expect(res.status).toBe(200);
    expect((await res.json()).accepted).toBe(2);
    expect(db.lakeBatch.create).toHaveBeenCalledTimes(1);
    const data = db.lakeBatch.create.mock.calls[0][0].data;
    expect(data).toMatchObject({ tenantId: "t1", agentId: "a1", eventCount: 2, receivedAt: new Date(NOW) });
    expect(data.events).toEqual([exec(), exec({ image_path: "/bin/ls" })]);
  });

  it("answers 500 when the batch cannot be queued, so the agent keeps its segment", async () => {
    process.env.LAKE_DIR = lakeDir;
    db.lakeBatch.create.mockRejectedValue(new Error("db down"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect((await postEvents({ events: [exec()] })).status).toBe(500);
    expect(db.agent.update).not.toHaveBeenCalled();
  });

  it("does not queue a batch with no accepted event", async () => {
    process.env.LAKE_DIR = lakeDir;
    expect((await postEvents({ events: [7, null] })).status).toBe(200);
    expect(db.lakeBatch.create).not.toHaveBeenCalled();
  });
});

describe("GET /api/cron/write-lake", () => {
  const call = (auth: string | null = "Bearer cron-secret") =>
    writeLake(new NextRequest("http://localhost/api/cron/write-lake", { headers: auth ? { Authorization: auth } : {} }));

  it("refuses a call without the cron secret and drains nothing", async () => {
    process.env.LAKE_DIR = lakeDir;
    expect((await call(null)).status).toBe(401);
    expect((await call("Bearer nope")).status).toBe(401);
    expect(db.$transaction).not.toHaveBeenCalled();
  });

  it("answers 503 while the lake is off", async () => {
    expect((await call()).status).toBe(503);
    expect(db.$transaction).not.toHaveBeenCalled();
  });

  it("drains the queue into files under LAKE_DIR and reports the counts", async () => {
    process.env.LAKE_DIR = lakeDir;
    process.env.LAKE_WRITER_MAX_BATCHES = "5";
    const batch = { id: "b1", tenantId: "t1", agentId: "a1", receivedAt: new Date(NOW), events: [exec()] };
    const tx = {
      $queryRaw: vi.fn().mockResolvedValue([{ id: "b1" }]),
      lakeBatch: { findMany: vi.fn().mockResolvedValue([batch]), deleteMany: vi.fn().mockResolvedValue({ count: 1 }), count: vi.fn().mockResolvedValue(0) },
      tenant: { findMany: vi.fn().mockResolvedValue([{ id: "t1", lakeRetentionDays: 90 }]) },
    };
    db.$transaction.mockImplementation(async (fn: (t: typeof tx) => Promise<unknown>) => fn(tx));
    const res = await call();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ batches: 1, events: 1, files: 1, droppedNoRetention: 0, skippedMalformed: 0, remaining: 0, maxBatches: 5 });
    const files = await readdir(path.join(lakeDir, "tenant=t1/date=2026-10-29/type=exec"));
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^[0-9a-f]{32}\.parquet$/);
    expect(tx.lakeBatch.deleteMany).toHaveBeenCalledWith({ where: { id: { in: ["b1"] } } });
  });

  it("refuses a LAKE_WRITER_MAX_BATCHES that is set but wrong", async () => {
    process.env.LAKE_DIR = lakeDir;
    process.env.LAKE_WRITER_MAX_BATCHES = "lots";
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect((await call()).status).toBe(500);
    expect(db.$transaction).not.toHaveBeenCalled();
  });

  it("answers 500 and leaves the queue alone when the drain fails", async () => {
    process.env.LAKE_DIR = lakeDir;
    db.$transaction.mockRejectedValue(new Error("db down"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect((await call()).status).toBe(500);
  });
});
