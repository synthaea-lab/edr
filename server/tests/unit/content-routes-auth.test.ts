import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// Route logic runs against a mocked Prisma client, so these need no database.
const db = vi.hoisted(() => ({
  agent: { findUnique: vi.fn() },
  contentRelease: { findFirst: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { GET as getManifest } from "@/app/api/content/manifest/[ring]/route";
import { GET as getArtifact } from "@/app/api/content/artifact/route";

const SECRET = "test-proxy-secret";

const MTLS = {
  "X-Client-Cert-Verified": "SUCCESS",
  "X-Client-Cert-Subject": "CN=agent-1,O=synthaea",
};

const manifestReq = (headers: Record<string, string>) =>
  new NextRequest("http://localhost/api/content/manifest/canary_0", { headers });
const artifactReq = (headers: Record<string, string>) =>
  new NextRequest("http://localhost/api/content/artifact?path=rules/a.sigma", { headers });

const callManifest = (headers: Record<string, string>) =>
  getManifest(manifestReq(headers), { params: { ring: "canary_0" } });

beforeEach(() => {
  vi.clearAllMocks();
  process.env.NGINX_PROXY_SECRET = SECRET;
  db.agent.findUnique.mockResolvedValue({ id: "a1", tenantId: "t1", ring: "canary_0" });
  db.contentRelease.findFirst.mockResolvedValue(null);
});

describe("agent content routes authentication (issue #30)", () => {
  // Regression: both routes trusted the X-Client-Cert-* headers without the
  // proxy secret, so anyone reaching the app directly could forge an agent.
  it("refuses forged mTLS headers that did not come through the proxy", async () => {
    for (const [name, res] of [
      ["manifest", await callManifest(MTLS)],
      ["artifact", await getArtifact(artifactReq(MTLS))],
    ] as const) {
      expect(res.status, name).toBe(403);
    }
    expect(db.agent.findUnique).not.toHaveBeenCalled();
  });

  it("refuses a wrong proxy secret", async () => {
    const headers = { ...MTLS, "X-Proxy-Secret": "not-the-secret" };
    expect((await callManifest(headers)).status).toBe(403);
    expect((await getArtifact(artifactReq(headers))).status).toBe(403);
  });

  it("refuses a request without a verified client certificate", async () => {
    const headers = { "X-Proxy-Secret": SECRET };
    expect((await callManifest(headers)).status).toBe(401);
    expect((await getArtifact(artifactReq(headers))).status).toBe(401);
  });

  it("refuses an agent that is not enrolled", async () => {
    db.agent.findUnique.mockResolvedValue(null);
    const headers = { ...MTLS, "X-Proxy-Secret": SECRET };
    expect((await callManifest(headers)).status).toBe(403);
    expect((await getArtifact(artifactReq(headers))).status).toBe(403);
  });

  it("still enforces the agent's own ring on the manifest", async () => {
    db.agent.findUnique.mockResolvedValue({ id: "a1", tenantId: "t1", ring: "prod" });
    const res = await callManifest({ ...MTLS, "X-Proxy-Secret": SECRET });
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe("Ring mismatch");
  });

  it("lets an authenticated agent through to the route logic", async () => {
    const headers = { ...MTLS, "X-Proxy-Secret": SECRET };
    // No active release row: past authentication the route answers 404.
    expect((await callManifest(headers)).status).toBe(404);
    // Past authentication the artifact route reads storage, which has no such file here.
    expect((await getArtifact(artifactReq(headers))).status).toBe(404);
  });

  it("passes a halted-ring response through both manifest and artifact routes", async () => {
    db.contentRelease.findFirst.mockResolvedValue({ releaseVersion: 2, status: "halted" });
    const headers = { ...MTLS, "X-Proxy-Secret": SECRET };

    const manifest = await callManifest(headers);
    const artifact = await getArtifact(artifactReq(headers));

    expect(manifest.status).toBe(423);
    expect((await manifest.json()).error).toMatch(/halted/i);
    expect(artifact.status).toBe(423);
    expect((await artifact.json()).error).toMatch(/halted/i);
  });
});
