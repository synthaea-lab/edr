import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const db = vi.hoisted(() => ({ $transaction: vi.fn() }));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { POST } from "@/app/api/hunts/search/route";
import { FsLakeStore } from "@/lib/lake-store";
import { encodeParquet, lakeKey, lakeRow } from "@/lib/lake-writer";

const TODAY = new Date().toISOString().slice(0, 10);
const eventQuery = { kind: "events", version: 1, lastDays: 2 };

let dir: string;
let slotFree: boolean;
beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), "hunt-events-route-"));
  delete process.env.LAKE_DIR;
  slotFree = true;
  const tx = { $queryRaw: vi.fn(async () => [{ ok: slotFree }]) };
  db.$transaction.mockReset();
  db.$transaction.mockImplementation(async (fn: (t: typeof tx) => Promise<unknown>) => fn(tx));
});
afterEach(async () => {
  delete process.env.LAKE_DIR;
  await rm(dir, { recursive: true, force: true });
});

async function put(tenant: string, agent: string) {
  const event = { type: "exec", meta: { comm: "bash" } };
  await new FsLakeStore(dir).put(lakeKey(tenant, TODAY, "exec", "a"), encodeParquet([lakeRow(agent, event, new Date(), JSON.stringify(event))]));
}
const post = (body: unknown, tenant: string | null = "t-session") =>
  POST(
    new NextRequest("http://localhost/api/hunts/search", {
      method: "POST",
      headers: tenant ? { "x-tenant-id": tenant } : {},
      body: JSON.stringify(body),
    })
  );

describe("POST /api/hunts/search with source events", () => {
  it("answers 503 while the lake is off, and takes no slot", async () => {
    const res = await post({ source: "events", query: eventQuery });
    expect(res.status).toBe(503);
    expect(db.$transaction).not.toHaveBeenCalled();
  });

  it("searches the session's tenant, whatever the body says about another one", async () => {
    process.env.LAKE_DIR = dir;
    await put("t-session", "mine");
    await put("t-other", "theirs");
    const ok = await post({ source: "events", query: eventQuery });
    expect(ok.status).toBe(200);
    const page = await ok.json();
    expect(page).toMatchObject({ source: "events", truncated: false, incomplete: false });
    expect(page.rows.map((r: { agentId: string }) => r.agentId)).toEqual(["mine"]);

    for (const body of [
      { source: "events", query: eventQuery, tenantId: "t-other" },
      { source: "events", query: { ...eventQuery, tenantId: "t-other" } },
      { source: "events", query: { ...eventQuery, where: { tenantId: "t-other" } } },
    ]) {
      const res = await post(body);
      expect(res.status, JSON.stringify(body)).toBe(400);
    }
    // Another session sees only its own events, from the same body.
    const other = await (await post({ source: "events", query: eventQuery }, "t-other")).json();
    expect(other.rows.map((r: { agentId: string }) => r.agentId)).toEqual(["theirs"]);
  });

  it("answers 429 when the tenant's slots are taken, and 400 for a cursor", async () => {
    process.env.LAKE_DIR = dir;
    slotFree = false;
    const busy = await post({ source: "events", query: eventQuery });
    expect(busy.status).toBe(429);
    expect(busy.headers.get("Retry-After")).toBe("5");
    slotFree = true;
    expect((await post({ source: "events", query: eventQuery, cursor: "abc" })).status).toBe(400);
  });

  it("treats a lake directory that does not exist yet as an empty archive", async () => {
    process.env.LAKE_DIR = path.join(dir, "missing", "dir");
    const res = await post({ source: "events", query: eventQuery });
    expect(res.status).toBe(200);
    expect((await res.json()).rows).toEqual([]);
  });

  it("leaves the detection and case sources on the Postgres path", async () => {
    process.env.LAKE_DIR = dir;
    db.$transaction.mockRejectedValue(new Error("db down at host db:5432"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await post({ source: "detections", query: { version: 1, lastHours: 24 } });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "Internal server error" });
  });
});
