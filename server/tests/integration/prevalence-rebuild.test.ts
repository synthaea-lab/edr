import { mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { NextRequest } from "next/server";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { createMtlsHeaders } from "../helpers/http";
import { FsLakeStore } from "@/lib/lake-store";
import { dayOf, drainLakeQueue } from "@/lib/lake-writer";
import { compareSightings, isIdentical, rebuildSightings, type AgentSighting } from "@/lib/prevalence-rebuild";
import { POST } from "@/app/api/v1/ingest/events/route";

const SECRET = "test-proxy-secret";
const DAY = 86_400_000;
const SHA = "d".repeat(64);

let dir: string;
let store: FsLakeStore;

beforeEach(async () => {
  process.env.NGINX_PROXY_SECRET = SECRET;
  process.env.LAKE_DIR = dir = await mkdtemp(path.join(os.tmpdir(), "prev-rebuild-int-"));
  store = new FsLakeStore(dir);
  await cleanDatabase();
});
afterEach(async () => {
  delete process.env.LAKE_DIR;
  await rm(dir, { recursive: true, force: true });
});
afterAll(async () => {
  await cleanDatabase();
  await prisma.$disconnect();
});

function upload(enrollmentId: string, events: unknown[]) {
  return POST(
    new NextRequest("http://localhost/api/v1/ingest/events", {
      method: "POST",
      headers: { ...createMtlsHeaders(enrollmentId), "X-Proxy-Secret": SECRET },
      body: JSON.stringify({ agent_id: null, events }),
    })
  );
}
const stamp = (daysAgo: number, ms = 0) => ({ timestamp_ns: (Date.now() - daysAgo * DAY + ms) * 1_000_000 });
const exec = (daysAgo: number, over: Record<string, unknown> = {}) => ({
  type: "exec",
  meta: stamp(daysAgo),
  image_path: "/usr/bin/curl",
  parent_comm: "bash",
  sha256: SHA,
  ...over,
});

/** The counters ingest wrote for a tenant, in the shape the rebuild produces. */
async function tableOf(tenantId: string): Promise<AgentSighting[]> {
  const rows = await prisma.prevalenceSighting.findMany({ where: { tenantId } });
  return rows.map((r) => ({ agentId: r.agentId, kind: r.kind as AgentSighting["kind"], key: r.key, firstSeen: r.firstSeen, lastSeen: r.lastSeen, count: r.count }));
}
const range = () => ({ from: dayOf(new Date(Date.now() - 20 * DAY)), to: dayOf(new Date(Date.now() + DAY)) });

async function seed() {
  const tenant = await createTestTenant();
  await prisma.tenant.update({ where: { id: tenant.id }, data: { lakeRetentionDays: 365 } });
  const [a, b] = [await createTestAgent(tenant.id), await createTestAgent(tenant.id)];
  // Three uploads from a, two from b, on different days, the same key on both hosts, a Windows path,
  // a domain, an event with no usable time (judged at the upload's own time) and one dated in the future.
  await upload(a.enrollmentId, [exec(5), exec(5, { meta: stamp(5, 1) }), exec(4, { image_path: "C:\\Windows\\CMD.EXE", parent_comm: "", parent_image_path: "C:\\Windows\\Explorer.EXE", sha256: "" })]);
  await upload(a.enrollmentId, [{ type: "dns_query", meta: stamp(3), query: "Example.COM." }, exec(2)]);
  await upload(b.enrollmentId, [exec(4), { type: "exec", image_path: "/usr/bin/untimed", parent_comm: "bash" }, exec(-30, { image_path: "/usr/bin/future" })]);
  await upload(b.enrollmentId, [{ type: "file_open", meta: stamp(1), path: "/etc/passwd" }, { type: "exec", meta: stamp(1) }]);
  await drainLakeQueue(prisma, store);
  return { tenant, a, b };
}

describe("prevalence rebuilt from the lake (real database, real ingest route)", () => {
  it("reproduces the counters ingest wrote, row for row", async () => {
    const { tenant } = await seed();
    const table = await tableOf(tenant.id);
    expect(table.length).toBeGreaterThan(8);

    const rebuilt = await rebuildSightings(store, { tenantId: tenant.id, ...range() });
    expect(rebuilt).toMatchObject({ complete: true, skipped: 0 });
    const diff = compareSightings(rebuilt.sightings, table);
    expect(diff).toMatchObject({ onlyRebuilt: [], onlyTable: [], differing: [] });
    expect(isIdentical(diff)).toBe(true);
    expect(diff.matching).toBe(table.length);
  });

  it("keeps tenants apart: the other tenant's counters and lake are neither read nor matched", async () => {
    const { tenant } = await seed();
    const other = await createTestTenant();
    await prisma.tenant.update({ where: { id: other.id }, data: { lakeRetentionDays: 365 } });
    const o = await createTestAgent(other.id);
    await upload(o.enrollmentId, [exec(1, { image_path: "/tmp/other" })]);
    await drainLakeQueue(prisma, store);

    const rebuilt = await rebuildSightings(store, { tenantId: tenant.id, ...range() });
    expect(rebuilt.sightings.map((s) => s.key)).not.toContain("/tmp/other");
    expect(isIdentical(compareSightings(rebuilt.sightings, await tableOf(tenant.id)))).toBe(true);
  });

  it("shows a counter the lake no longer holds as `onlyTable`, not as a match", async () => {
    const { tenant } = await seed();
    const [oldest] = (await readdir(path.join(dir, `tenant=${tenant.id}`))).sort();
    await rm(path.join(dir, `tenant=${tenant.id}`, oldest), { recursive: true });

    const diff = compareSightings((await rebuildSightings(store, { tenantId: tenant.id, ...range() })).sightings, await tableOf(tenant.id));
    expect(isIdentical(diff)).toBe(false);
    expect(diff.onlyTable.length + diff.differing.length).toBeGreaterThan(0);
  });

  it("is what a replay of the same lake gives twice", async () => {
    const { tenant } = await seed();
    const first = await rebuildSightings(store, { tenantId: tenant.id, ...range() });
    const second = await rebuildSightings(store, { tenantId: tenant.id, ...range() });
    expect(second.sightings).toEqual(first.sightings);
  });
});
