import { describe, it, expect, beforeEach, afterAll, afterEach } from "vitest";
import { NextRequest } from "next/server";
import { createHash } from "crypto";
import { mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { cleanDatabase, createTestTenant, createTestAgent, prisma } from "../helpers/db";
import { createMtlsHeaders } from "../helpers/http";
import { GET as getManifest } from "@/app/api/release/manifest/route";
import { GET as getArtifact } from "@/app/api/release/artifact/route";

const SECRET = "integration-proxy-secret";
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const AGENT_BYTES = Buffer.from("agent binary v1");

function manifestBytes(version: number) {
  return Buffer.from(
    JSON.stringify({
      schema_version: 1,
      release_version: version,
      entries: { agent: sha(AGENT_BYTES) },
      signature: "00",
    })
  );
}

function agentRequest(url: string, enrollmentId: string) {
  return new NextRequest(url, {
    headers: { ...createMtlsHeaders(enrollmentId), "X-Proxy-Secret": SECRET },
  });
}

describe("binary release routes against a real database", () => {
  let originalCwd: string;
  let sandbox: string;

  beforeEach(async () => {
    await cleanDatabase();
    process.env.NGINX_PROXY_SECRET = SECRET;
    originalCwd = process.cwd();
    sandbox = join(originalCwd, ".test-sandbox-release");
    mkdirSync(join(sandbox, "storage", "manifests"), { recursive: true });
    mkdirSync(join(sandbox, "storage", "releases", "v1"), { recursive: true });
    process.chdir(sandbox);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    rmSync(sandbox, { recursive: true, force: true });
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  async function publish(tenantId: string, ring: string, version: number, status = "active") {
    const bytes = manifestBytes(version);
    writeFileSync(join(sandbox, "storage", "manifests", `release-${ring}-v${version}.json`), bytes);
    mkdirSync(join(sandbox, "storage", "releases", `v${version}`), { recursive: true });
    writeFileSync(join(sandbox, "storage", "releases", `v${version}`, "agent"), AGENT_BYTES);
    return prisma.binaryRelease.create({
      data: {
        tenantId,
        ring,
        releaseVersion: version,
        manifestUrl: `storage://manifests/release-${ring}-v${version}.json`,
        manifestSha256: sha(bytes),
        status,
        releasedAt: new Date(),
      },
    });
  }

  it("serves the latest active release of the agent's ring", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-1", { ring: "canary_0" });
    await publish(tenant.id, "canary_0", 1);
    await publish(tenant.id, "canary_0", 2);

    const res = await getManifest(agentRequest("http://localhost/api/release/manifest", "agent-1"));

    expect(res.status).toBe(200);
    expect((await res.json()).release_version).toBe(2);
  });

  it("skips a halted release and offers the previous active one", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-1", { ring: "canary_0" });
    await publish(tenant.id, "canary_0", 1);
    await publish(tenant.id, "canary_0", 2, "halted");

    const res = await getManifest(agentRequest("http://localhost/api/release/manifest", "agent-1"));

    expect((await res.json()).release_version).toBe(1);
  });

  it("never offers another ring's release", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-prod", { ring: "prod" });
    await publish(tenant.id, "canary_0", 1);

    const res = await getManifest(agentRequest("http://localhost/api/release/manifest", "agent-prod"));

    expect(res.status).toBe(404);
  });

  it("never offers another tenant's release", async () => {
    const tenantA = await createTestTenant();
    const tenantB = await createTestTenant();
    await createTestAgent(tenantB.id, "agent-b", { ring: "canary_0" });
    await publish(tenantA.id, "canary_0", 1);

    const manifest = await getManifest(agentRequest("http://localhost/api/release/manifest", "agent-b"));
    const artifact = await getArtifact(
      agentRequest("http://localhost/api/release/artifact?release_version=1&path=agent", "agent-b")
    );

    expect(manifest.status).toBe(404);
    expect(artifact.status).toBe(404);
  });

  it("serves an artifact of the agent's own release", async () => {
    const tenant = await createTestTenant();
    await createTestAgent(tenant.id, "agent-1", { ring: "canary_0" });
    await publish(tenant.id, "canary_0", 1);

    const res = await getArtifact(
      agentRequest("http://localhost/api/release/artifact?release_version=1&path=agent", "agent-1")
    );

    expect(res.status).toBe(200);
    expect(Buffer.from(await res.arrayBuffer()).equals(AGENT_BYTES)).toBe(true);
  });

  it("enforces one release per tenant, ring and version", async () => {
    const tenant = await createTestTenant();
    await publish(tenant.id, "canary_0", 1);
    await expect(publish(tenant.id, "canary_0", 1)).rejects.toMatchObject({ code: "P2002" });
  });
});
