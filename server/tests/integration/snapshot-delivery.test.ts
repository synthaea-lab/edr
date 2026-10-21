import { createHash } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { createMtlsHeaders } from "../helpers/http";
import { recordObservations } from "@/lib/prevalence";
import { parseCommonSetSnapshot } from "@/lib/common-set-snapshot";
import { publishCommonSetSnapshot } from "@/lib/snapshot-publish";
import { signerFromSeed, SnapshotManifest, TEST_SNAPSHOT_SEED, verifySnapshotManifest } from "@/lib/snapshot-manifest";
import { GET as getManifest } from "@/app/api/snapshot/manifest/route";
import { GET as getArtifact } from "@/app/api/snapshot/artifact/route";
import { GET as cron } from "@/app/api/cron/build-snapshots/route";

const signer = signerFromSeed(TEST_SNAPSHOT_SEED);
const SHA_COMMON = "a".repeat(64);
const SHA_RARE = "b".repeat(64);
const T0 = new Date(Date.UTC(2026, 9, 20, 12, 0, 0));
const later = (s: number) => new Date(T0.getTime() + s * 1000);

/** Three hosts: SHA_COMMON on all of them, SHA_RARE on one. */
async function fleet(tenantId: string) {
  const agents = [await createTestAgent(tenantId), await createTestAgent(tenantId), await createTestAgent(tenantId)];
  for (const a of agents) await recordObservations(prisma, tenantId, a.id, T0, [{ kind: "sha256", key: SHA_COMMON }]);
  await recordObservations(prisma, tenantId, agents[0].id, T0, [{ kind: "sha256", key: SHA_RARE }]);
  return agents;
}

const req = (url: string, enrollmentId: string, proxy = true) =>
  new NextRequest(`http://localhost${url}`, {
    headers: { ...createMtlsHeaders(enrollmentId), ...(proxy ? { "X-Proxy-Secret": "test-proxy-secret" } : {}) },
  });

describe("snapshot delivery (real database)", () => {
  beforeEach(async () => {
    process.env.NGINX_PROXY_SECRET = "test-proxy-secret";
    await cleanDatabase();
  });
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("publishes a signed snapshot whose artifact holds the common hash and not the rare one", async () => {
    const t = await createTestTenant();
    await fleet(t.id);

    const out = await publishCommonSetSnapshot(prisma, t.id, signer, T0, { minHosts: 2, minHostsCovered: 2 });
    expect(out).toMatchObject({ status: "published", hostsCovered: 3, entryCount: 1 });

    const row = await prisma.commonSetSnapshot.findUniqueOrThrow({ where: { tenantId: t.id } });
    const manifest = SnapshotManifest.parse(row.manifest);
    expect(verifySnapshotManifest(manifest, signer.publicKey())).toBe(true);
    expect(manifest).toMatchObject({ built_at: T0.getTime() / 1000, hosts_covered: 3, min_hosts: 2, entry_count: 1 });
    expect(manifest.sha256).toBe(createHash("sha256").update(row.artifact).digest("hex"));
    expect(manifest.size).toBe(row.artifact.length);
    const parsed = parseCommonSetSnapshot(row.artifact);
    expect(parsed.header).toMatchObject({ builtAt: manifest.built_at, hostsCovered: 3 });
    expect(parsed.contains(SHA_COMMON)).toBe(true);
    expect(parsed.contains(SHA_RARE)).toBe(false);
  });

  it("serves an enrolled agent its own tenant's manifest and bytes, and nothing of another tenant's", async () => {
    const mine = await createTestTenant();
    const other = await createTestTenant();
    const [agent] = await fleet(mine.id);
    const otherAgents = await fleet(other.id);
    await prisma.agent.update({ where: { id: otherAgents[0].id }, data: { hostname: "other" } });
    await publishCommonSetSnapshot(prisma, mine.id, signer, T0, { minHosts: 2, minHostsCovered: 2 });
    // The other tenant's snapshot is built later, so the two differ in built_at.
    await publishCommonSetSnapshot(prisma, other.id, signer, later(60), { minHosts: 2, minHostsCovered: 2 });

    const manifest = await (await getManifest(req("/api/snapshot/manifest", agent.enrollmentId))).json();
    expect(manifest.built_at).toBe(T0.getTime() / 1000);

    const res = await getArtifact(req(`/api/snapshot/artifact?sha256=${manifest.sha256}`, agent.enrollmentId));
    expect(res.status).toBe(200);
    const bytes = Buffer.from(await res.arrayBuffer());
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(manifest.sha256);
    expect(res.headers.get("content-length")).toBe(String(bytes.length));
  });

  it("answers 404 when no snapshot was published, 409 for a hash that is not the stored one", async () => {
    const t = await createTestTenant();
    const [agent] = await fleet(t.id);
    expect((await getManifest(req("/api/snapshot/manifest", agent.enrollmentId))).status).toBe(404);
    expect((await getArtifact(req("/api/snapshot/artifact", agent.enrollmentId))).status).toBe(404);

    await publishCommonSetSnapshot(prisma, t.id, signer, T0, { minHosts: 2, minHostsCovered: 2 });
    const res = await getArtifact(req(`/api/snapshot/artifact?sha256=${"0".repeat(64)}`, agent.enrollmentId));
    expect(res.status).toBe(409);
  });

  it("refuses a caller without the proxy secret or an enrolled certificate", async () => {
    const t = await createTestTenant();
    const [agent] = await fleet(t.id);
    await publishCommonSetSnapshot(prisma, t.id, signer, T0, { minHosts: 2, minHostsCovered: 2 });
    expect((await getManifest(req("/api/snapshot/manifest", agent.enrollmentId, false))).status).toBe(403);
    expect((await getManifest(req("/api/snapshot/manifest", "nobody"))).status).toBe(403);
    expect((await getArtifact(req("/api/snapshot/artifact", "nobody"))).status).toBe(403);
  });

  it("replaces the snapshot with a later build and refuses one that is not later", async () => {
    const t = await createTestTenant();
    await fleet(t.id);
    const p = { minHosts: 2, minHostsCovered: 2 };
    await publishCommonSetSnapshot(prisma, t.id, signer, T0, p);
    expect(await publishCommonSetSnapshot(prisma, t.id, signer, T0, p)).toMatchObject({ status: "skipped", reason: expect.stringMatching(/not later/) });
    expect(await publishCommonSetSnapshot(prisma, t.id, signer, later(3600), p)).toMatchObject({ status: "published" });
    expect(await prisma.commonSetSnapshot.count({ where: { tenantId: t.id } })).toBe(1);
    expect((await prisma.commonSetSnapshot.findUniqueOrThrow({ where: { tenantId: t.id } })).builtAt).toEqual(later(3600));
  });

  it("keeps the previous snapshot served when the next build is truncated", async () => {
    const t = await createTestTenant();
    const agents = await fleet(t.id);
    for (let i = 0; i < 9; i++) {
      for (const a of agents) await recordObservations(prisma, t.id, a.id, T0, [{ kind: "sha256", key: String(i).repeat(64) }]);
    }
    const p = { minHosts: 2, minHostsCovered: 2 };
    await publishCommonSetSnapshot(prisma, t.id, signer, T0, p);
    const before = await prisma.commonSetSnapshot.findUniqueOrThrow({ where: { tenantId: t.id } });
    expect(before.entryCount).toBe(10);

    // The same hosts now count a hash only at 4 hosts: almost nothing is common, no host fewer.
    const out = await publishCommonSetSnapshot(prisma, t.id, signer, later(3600), { ...p, minHosts: 4 });
    expect(out).toMatchObject({ status: "skipped", reason: expect.stringMatching(/truncated/) });
    const after = await prisma.commonSetSnapshot.findUniqueOrThrow({ where: { tenantId: t.id } });
    expect(after.builtAt).toEqual(before.builtAt);
  });

  it("builds nothing for a tenant with too few hosts, and refuses to truncate a huge set", async () => {
    const t = await createTestTenant();
    const a = await createTestAgent(t.id);
    await recordObservations(prisma, t.id, a.id, T0, [{ kind: "sha256", key: SHA_COMMON }]);
    expect(await publishCommonSetSnapshot(prisma, t.id, signer, T0, { minHosts: 1, minHostsCovered: 2 })).toMatchObject({
      status: "skipped",
      reason: expect.stringMatching(/only 1 hosts/),
    });
    await fleet(t.id);
    expect(await publishCommonSetSnapshot(prisma, t.id, signer, T0, { minHosts: 1, minHostsCovered: 2, maxEntries: 1 })).toMatchObject({
      status: "skipped",
      reason: expect.stringMatching(/raise K/),
    });
    expect(await prisma.commonSetSnapshot.count()).toBe(0);
  });

  describe("GET /api/cron/build-snapshots", () => {
    const call = () =>
      cron(new NextRequest("http://localhost/api/cron/build-snapshots", { headers: { Authorization: "Bearer cron-secret" } }));

    beforeEach(() => {
      process.env.CRON_SECRET = "cron-secret";
      delete process.env.SYNTHAEA_SNAPSHOT_SIGNER;
    });

    it("answers 503 and builds nothing when no signer is configured", async () => {
      const t = await createTestTenant();
      await fleet(t.id);
      expect((await call()).status).toBe(503);
      expect(await prisma.commonSetSnapshot.count()).toBe(0);
    });

    it("builds every tenant's snapshot with the test signer, one failing tenant not stopping the rest", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      process.env.SYNTHAEA_SNAPSHOT_SIGNER = "test";
      const a = await createTestTenant();
      const b = await createTestTenant();
      const empty = await createTestTenant();
      await fleet(a.id);
      await fleet(b.id);

      const res = await call();
      expect(res.status).toBe(200);
      const body = await res.json();
      const status = (id: string) => body.results.find((r: { tenantId: string }) => r.tenantId === id).status;
      expect(status(a.id)).toBe("published");
      expect(status(b.id)).toBe("published");
      expect(status(empty.id)).toBe("skipped");
      warn.mockRestore();
      delete process.env.SYNTHAEA_SNAPSHOT_SIGNER;
    });

    it("refuses a call without the cron secret", async () => {
      const res = await cron(new NextRequest("http://localhost/api/cron/build-snapshots"));
      expect(res.status).toBe(401);
    });
  });
});
