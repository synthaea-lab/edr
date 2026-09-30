import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createHash } from "crypto";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join } from "path";

// Route logic runs against a mocked Prisma client, so these need no database.
const db = vi.hoisted(() => ({
  agent: { findUnique: vi.fn() },
  binaryRelease: { findFirst: vi.fn(), findMany: vi.fn(), create: vi.fn() },
  auditLog: { create: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { GET as getManifest } from "@/app/api/release/manifest/route";
import { GET as getArtifact } from "@/app/api/release/artifact/route";
import { GET as listReleases, POST as publish } from "@/app/api/release/route";

const SECRET = "test-proxy-secret";
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

const AGENT_BYTES = Buffer.from("#!/bin/sh\necho agent v2\n");
const WATCHDOG_BYTES = Buffer.from("#!/bin/sh\necho watchdog v2\n");

function manifestJson(overrides: Record<string, unknown> = {}) {
  return Buffer.from(
    JSON.stringify({
      schema_version: 1,
      release_version: 2,
      entries: { agent: sha(AGENT_BYTES), watchdog: sha(WATCHDOG_BYTES) },
      signature: "00",
      ...overrides,
    })
  );
}

function agentHeaders(extra: Record<string, string> = {}) {
  return {
    "X-Proxy-Secret": SECRET,
    "X-Client-Cert-Verified": "SUCCESS",
    "X-Client-Cert-Subject": "CN=agent-1,O=synthaea",
    ...extra,
  };
}

const AGENT = { id: "a1", tenantId: "t1", ring: "canary_0" };

function releaseRow(manifest: Buffer, overrides: Record<string, unknown> = {}) {
  return {
    id: "r1",
    tenantId: "t1",
    ring: "canary_0",
    releaseVersion: 2,
    manifestUrl: "storage://manifests/release-canary_0-v2.json",
    manifestSha256: sha(manifest),
    status: "active",
    ...overrides,
  };
}

let originalCwd: string;
let sandbox: string;

function store(manifest: Buffer, artifacts: Record<string, Buffer> = { agent: AGENT_BYTES, watchdog: WATCHDOG_BYTES }) {
  writeFileSync(join(sandbox, "storage", "manifests", "release-canary_0-v2.json"), manifest);
  for (const [name, bytes] of Object.entries(artifacts)) {
    writeFileSync(join(sandbox, "storage", "releases", "v2", name), bytes);
  }
}

beforeEach(() => {
  vi.clearAllMocks();
  process.env.NGINX_PROXY_SECRET = SECRET;
  originalCwd = process.cwd();
  sandbox = join(originalCwd, ".test-sandbox-release-routes");
  mkdirSync(join(sandbox, "storage", "manifests"), { recursive: true });
  mkdirSync(join(sandbox, "storage", "releases", "v2"), { recursive: true });
  process.chdir(sandbox);
  db.agent.findUnique.mockResolvedValue(AGENT);
});

afterEach(() => {
  process.chdir(originalCwd);
  rmSync(sandbox, { recursive: true, force: true });
});

function manifestRequest(headers: Record<string, string> = agentHeaders()) {
  return new NextRequest("http://localhost/api/release/manifest", { headers });
}

function artifactRequest(query: string, headers: Record<string, string> = agentHeaders()) {
  return new NextRequest(`http://localhost/api/release/artifact?${query}`, { headers });
}

describe("agent authentication (both agent routes)", () => {
  it.each([
    ["manifest", () => getManifest(manifestRequest(agentHeaders({ "X-Proxy-Secret": "wrong" })))],
    ["artifact", () => getArtifact(artifactRequest("release_version=2&path=agent", agentHeaders({ "X-Proxy-Secret": "wrong" })))],
  ])("%s: a request that did not come through the proxy is forbidden", async (_n, call) => {
    // Without this, anyone reaching the app directly could forge the mTLS headers.
    expect((await call()).status).toBe(403);
    expect(db.binaryRelease.findFirst).not.toHaveBeenCalled();
  });

  it("without a verified client certificate the request is unauthorized", async () => {
    const res = await getManifest(manifestRequest(agentHeaders({ "X-Client-Cert-Verified": "NONE" })));
    expect(res.status).toBe(401);
  });

  it("an unenrolled agent is forbidden", async () => {
    db.agent.findUnique.mockResolvedValue(null);
    expect((await getManifest(manifestRequest())).status).toBe(403);
  });
});

describe("GET /api/release/manifest", () => {
  it("serves the latest active release of the agent's own ring", async () => {
    const manifest = manifestJson();
    store(manifest);
    db.binaryRelease.findFirst.mockResolvedValue(releaseRow(manifest));

    const res = await getManifest(manifestRequest());

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(JSON.parse(manifest.toString()));
    expect(db.binaryRelease.findFirst).toHaveBeenCalledWith({
      where: { tenantId: "t1", ring: "canary_0", status: "active" },
      orderBy: { releaseVersion: "desc" },
    });
  });

  it("is 404 when the ring has no active release", async () => {
    db.binaryRelease.findFirst.mockResolvedValue(null);
    expect((await getManifest(manifestRequest())).status).toBe(404);
  });

  it("refuses to serve a manifest whose bytes no longer hash to the stored value", async () => {
    const manifest = manifestJson();
    store(manifestJson({ signature: "tampered" }));
    db.binaryRelease.findFirst.mockResolvedValue(releaseRow(manifest));
    expect((await getManifest(manifestRequest())).status).toBe(502);
  });

  it("refuses a manifest whose own release_version disagrees with its row", async () => {
    const manifest = manifestJson({ release_version: 9 });
    store(manifest);
    db.binaryRelease.findFirst.mockResolvedValue(releaseRow(manifest));
    expect((await getManifest(manifestRequest())).status).toBe(502);
  });

  it("refuses a stored manifest with an escaping entry path", async () => {
    const manifest = manifestJson({ entries: { "../../etc/x": sha("x") } });
    store(manifest);
    db.binaryRelease.findFirst.mockResolvedValue(releaseRow(manifest));
    expect((await getManifest(manifestRequest())).status).toBe(502);
  });
});

describe("GET /api/release/artifact", () => {
  async function serve(query: string, headers?: Record<string, string>) {
    const manifest = manifestJson();
    store(manifest);
    db.binaryRelease.findFirst.mockResolvedValue(releaseRow(manifest));
    return getArtifact(artifactRequest(query, headers));
  }

  it("serves a listed file of an active release with its signed hash", async () => {
    const res = await serve(`release_version=2&path=agent&sha256=${sha(AGENT_BYTES)}`);
    expect(res.status).toBe(200);
    expect(Buffer.from(await res.arrayBuffer()).equals(AGENT_BYTES)).toBe(true);
    expect(res.headers.get("X-Content-SHA256")).toBe(sha(AGENT_BYTES));
    expect(db.binaryRelease.findFirst).toHaveBeenCalledWith({
      where: { tenantId: "t1", ring: "canary_0", releaseVersion: 2, status: "active" },
    });
  });

  it.each([
    "path=agent",
    "release_version=abc&path=agent",
    "release_version=0&path=agent",
    "release_version=2",
  ])("rejects a malformed request (%s)", async (query) => {
    expect((await serve(query)).status).toBe(400);
  });

  it.each(["../storage/manifests/release-canary_0-v2.json", "/etc/passwd", "constructor", "__proto__", "not-listed"])(
    "serves only paths the manifest lists (%s)",
    async (p) => {
      const res = await serve(`release_version=2&path=${encodeURIComponent(p)}`);
      expect(res.status).toBe(404);
    }
  );

  it("is 404 for a release that is not active for the agent's ring", async () => {
    db.binaryRelease.findFirst.mockResolvedValue(null);
    expect((await getArtifact(artifactRequest("release_version=2&path=agent"))).status).toBe(404);
  });

  it("is 409 when the caller expected a different hash than the signed one", async () => {
    const res = await serve(`release_version=2&path=agent&sha256=${"b".repeat(64)}`);
    expect(res.status).toBe(409);
  });

  it("is 502 when the stored file no longer matches the signed manifest", async () => {
    const manifest = manifestJson();
    store(manifest, { agent: Buffer.from("swapped on disk"), watchdog: WATCHDOG_BYTES });
    db.binaryRelease.findFirst.mockResolvedValue(releaseRow(manifest));
    const res = await getArtifact(artifactRequest("release_version=2&path=agent"));
    expect(res.status).toBe(502);
  });

  it("is 404 when the manifest lists a file that is missing from storage", async () => {
    const manifest = manifestJson();
    store(manifest, { watchdog: WATCHDOG_BYTES });
    db.binaryRelease.findFirst.mockResolvedValue(releaseRow(manifest));
    const res = await getArtifact(artifactRequest("release_version=2&path=agent"));
    expect(res.status).toBe(404);
  });
});

describe("POST /api/release (publish)", () => {
  function post(body: unknown) {
    return new NextRequest("http://localhost/api/release", {
      method: "POST",
      headers: { "x-tenant-id": "t1", "x-user-id": "u1", "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  function publishBody(manifest: Buffer, overrides: Record<string, unknown> = {}) {
    return {
      ring: "canary_0",
      releaseVersion: 2,
      manifestUrl: "storage://manifests/release-canary_0-v2.json",
      manifestSha256: sha(manifest),
      ...overrides,
    };
  }

  beforeEach(() => {
    db.binaryRelease.findFirst.mockResolvedValue(null);
    db.binaryRelease.create.mockImplementation(async ({ data }) => ({ id: "new", ...data }));
    db.auditLog.create.mockResolvedValue({});
  });

  it("publishes a release whose manifest and artifacts are all in storage", async () => {
    const manifest = manifestJson();
    store(manifest);
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(200);
    expect(db.binaryRelease.create).toHaveBeenCalledOnce();
    expect(db.auditLog.create).toHaveBeenCalledOnce();
  });

  it("refuses a release that is not newer than the ring's latest", async () => {
    const manifest = manifestJson();
    store(manifest);
    db.binaryRelease.findFirst.mockResolvedValue({ releaseVersion: 2 });
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(409);
    expect(db.binaryRelease.create).not.toHaveBeenCalled();
  });

  it("refuses to publish when an artifact is missing from storage", async () => {
    const manifest = manifestJson();
    store(manifest, { watchdog: WATCHDOG_BYTES });
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(422);
    expect(db.binaryRelease.create).not.toHaveBeenCalled();
  });

  it("refuses to publish when an artifact does not hash to its signed value", async () => {
    const manifest = manifestJson();
    store(manifest, { agent: Buffer.from("not the signed bytes"), watchdog: WATCHDOG_BYTES });
    expect((await publish(post(publishBody(manifest)))).status).toBe(422);
  });

  it("refuses when the supplied manifest hash or version does not match the file", async () => {
    const manifest = manifestJson();
    store(manifest);
    expect((await publish(post(publishBody(manifest, { manifestSha256: "c".repeat(64) })))).status).toBe(422);
    expect((await publish(post(publishBody(manifest, { releaseVersion: 3 })))).status).toBe(422);
  });

  it("rejects an invalid body", async () => {
    const res = await publish(post({ ring: "nope", releaseVersion: 0 }));
    expect(res.status).toBe(400);
  });

  it("without a tenant context it is not served", async () => {
    const res = await publish(
      new NextRequest("http://localhost/api/release", {
        method: "POST",
        body: JSON.stringify(publishBody(manifestJson())),
      })
    );
    expect(res.status).toBe(500);
  });
});

describe("GET /api/release (list)", () => {
  it("lists only the caller's tenant", async () => {
    db.binaryRelease.findMany.mockResolvedValue([]);
    const res = await listReleases(
      new NextRequest("http://localhost/api/release?ring=prod", { headers: { "x-tenant-id": "t1" } })
    );
    expect(res.status).toBe(200);
    expect(db.binaryRelease.findMany.mock.calls[0][0].where).toEqual({ tenantId: "t1", ring: "prod" });
  });
});
