import { describe, it, expect, beforeEach, afterAll, afterEach } from "vitest";
import { NextRequest } from "next/server";
import { generateKeyPairSync, sign as ed25519Sign, createHash } from "crypto";
import { mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { cleanDatabase, createTestTenant, createTestAgent, prisma } from "../helpers/db";
import { createMtlsHeaders } from "../helpers/http";
import { canonicalJSON, type ContentManifest } from "@/lib/content-manifest";
import { GET } from "@/app/api/content/manifest/[ring]/route";

const { privateKey } = generateKeyPairSync("ed25519");

function request(enrollmentId: string) {
  return new NextRequest("http://localhost/api/content/manifest/canary_0", {
    headers: createMtlsHeaders(enrollmentId),
  });
}

/** Signs with a throwaway Ed25519 key — this test never calls
 * `verifySignature`, only the manifest route's own integrity/shape checks
 * (sha256 against `manifestSha256`, Zod shape, ring/version agreement with
 * the DB row); which key signed it is irrelevant here. */
function signedManifestBytes(overrides: Partial<Omit<ContentManifest, "signature">>): Buffer {
  const unsigned: Omit<ContentManifest, "signature"> = {
    schema_version: 1,
    release_version: 1,
    ring: "canary_0",
    released_at: "2026-09-23T16:00:00Z",
    entries: [
      {
        path: "rules/beacon.sigma",
        type: "rule",
        sha256: "a".repeat(64),
        size: 1234,
      },
    ],
    ...overrides,
  };
  const canonical = canonicalJSON(unsigned);
  const signature = ed25519Sign(null, Buffer.from(canonical), privateKey).toString("hex");
  const manifest: ContentManifest = { ...unsigned, signature };
  return Buffer.from(JSON.stringify(manifest));
}

describe("GET /api/content/manifest/[ring]", () => {
  let originalCwd: string;
  let sandboxDir: string;

  beforeEach(async () => {
    await cleanDatabase();
    // The route reads storage:// manifests from process.cwd()/storage — run
    // each test against a throwaway cwd rather than the real repo's storage/.
    originalCwd = process.cwd();
    sandboxDir = join(originalCwd, ".test-sandbox-content-manifest");
    mkdirSync(join(sandboxDir, "storage", "manifests"), { recursive: true });
    process.chdir(sandboxDir);
  });

  afterEach(() => {
    if (originalCwd) {
      process.chdir(originalCwd);
    }
    if (sandboxDir) {
      rmSync(sandboxDir, { recursive: true, force: true });
    }
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  function writeManifestFile(filename: string, bytes: Buffer) {
    writeFileSync(join(sandboxDir, "storage", "manifests", filename), bytes);
  }

  it("returns the real signed manifest, not a placeholder", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-1", { ring: "canary_0" });

    const bytes = signedManifestBytes({ release_version: 1 });
    writeManifestFile("content-canary_0-v1.json", bytes);
    const sha256 = createHash("sha256").update(bytes).digest("hex");

    await prisma.contentRelease.create({
      data: {
        tenantId: tenant.id,
        ring: "canary_0",
        releaseVersion: 1,
        manifestUrl: "storage://manifests/content-canary_0-v1.json",
        manifestSha256: sha256,
        releasedAt: new Date(),
      },
    });

    const res = await GET(request("agent-1"), { params: { ring: "canary_0" } });
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.signature).not.toBe("placeholder_signature");
    expect(body.entries).toHaveLength(1);
    expect(body.entries[0].path).toBe("rules/beacon.sigma");
  });

  it("rejects when the manifest bytes don't match manifestSha256", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-2", { ring: "canary_0" });

    const bytes = signedManifestBytes({ release_version: 1 });
    writeManifestFile("content-canary_0-v1.json", bytes);

    await prisma.contentRelease.create({
      data: {
        tenantId: tenant.id,
        ring: "canary_0",
        releaseVersion: 1,
        manifestUrl: "storage://manifests/content-canary_0-v1.json",
        manifestSha256: "f".repeat(64), // wrong on purpose
        releasedAt: new Date(),
      },
    });

    const res = await GET(request("agent-2"), { params: { ring: "canary_0" } });
    expect(res.status).toBe(502);
    const body = await res.json();
    expect(body.error).toMatch(/integrity/i);
  });

  it("rejects when the manifest's own ring disagrees with the release row", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-3", { ring: "canary_0" });

    // Manifest content says canary_0, but stored under a release row that
    // (via a hypothetical upload mixup) points a canary_0 release's URL at a
    // prod-signed manifest.
    const bytes = signedManifestBytes({ release_version: 1, ring: "prod" });
    writeManifestFile("content-mismatch-v1.json", bytes);
    const sha256 = createHash("sha256").update(bytes).digest("hex");

    await prisma.contentRelease.create({
      data: {
        tenantId: tenant.id,
        ring: "canary_0",
        releaseVersion: 1,
        manifestUrl: "storage://manifests/content-mismatch-v1.json",
        manifestSha256: sha256,
        releasedAt: new Date(),
      },
    });

    const res = await GET(request("agent-3"), { params: { ring: "canary_0" } });
    expect(res.status).toBe(502);
    const body = await res.json();
    expect(body.error).toMatch(/ring mismatch/i);
  });

  it("rejects when the manifest's release_version disagrees with the release row", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-4", { ring: "canary_0" });

    const bytes = signedManifestBytes({ release_version: 99 });
    writeManifestFile("content-canary_0-v1.json", bytes);
    const sha256 = createHash("sha256").update(bytes).digest("hex");

    await prisma.contentRelease.create({
      data: {
        tenantId: tenant.id,
        ring: "canary_0",
        releaseVersion: 1, // the row says 1, the manifest bytes say 99
        manifestUrl: "storage://manifests/content-canary_0-v1.json",
        manifestSha256: sha256,
        releasedAt: new Date(),
      },
    });

    const res = await GET(request("agent-4"), { params: { ring: "canary_0" } });
    expect(res.status).toBe(502);
    const body = await res.json();
    expect(body.error).toMatch(/release_version mismatch/i);
  });

  it("returns 502 naming the failure when the manifest artifact is missing", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-5", { ring: "canary_0" });

    await prisma.contentRelease.create({
      data: {
        tenantId: tenant.id,
        ring: "canary_0",
        releaseVersion: 1,
        manifestUrl: "storage://manifests/does-not-exist.json",
        manifestSha256: "a".repeat(64),
        releasedAt: new Date(),
      },
    });

    const res = await GET(request("agent-5"), { params: { ring: "canary_0" } });
    expect(res.status).toBe(502);
  });

  it("still enforces ring-spoofing and tenant isolation ahead of the manifest fetch", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-6", { ring: "prod" });

    const res = await GET(request("agent-6"), { params: { ring: "canary_0" } });
    expect(res.status).toBe(403);
  });
});
