import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createHash } from "crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const db = vi.hoisted(() => ({ agent: { findUnique: vi.fn() } }));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
const active = vi.hoisted(() => ({ loadActiveManifest: vi.fn() }));
vi.mock("@/lib/active-content-manifest", () => active);

import { GET } from "@/app/api/content/artifact/route";

const SECRET = "test-proxy-secret";
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const RULE = Buffer.from("title: beacon\n");
const OTHER = Buffer.from("title: another ring's unreleased rule\n");

const manifestWith = (entries: { path: string; sha256: string }[]) => ({
  ok: true,
  manifest: {
    schema_version: 1,
    release_version: 3,
    ring: "canary_0",
    released_at: "2026-10-01T00:00:00Z",
    entries: entries.map((e) => ({ ...e, type: "rule", size: 1 })),
    signature: "00",
  },
});

const call = (query: string) =>
  GET(
    new NextRequest(`http://localhost/api/content/artifact?${query}`, {
      headers: {
        "X-Client-Cert-Verified": "SUCCESS",
        "X-Client-Cert-Subject": "CN=agent-1,O=synthaea",
        "X-Proxy-Secret": SECRET,
      },
    })
  );

describe("GET /api/content/artifact is scoped to the agent's own manifest (issue #30)", () => {
  let originalCwd: string;
  let sandbox: string;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.NGINX_PROXY_SECRET = SECRET;
    db.agent.findUnique.mockResolvedValue({ id: "a1", tenantId: "t1", ring: "canary_0" });
    originalCwd = process.cwd();
    sandbox = mkdtempSync(join(tmpdir(), "artifact-scope-"));
    mkdirSync(join(sandbox, "storage", "artifacts", "rules"), { recursive: true });
    writeFileSync(join(sandbox, "storage", "artifacts", "rules", "beacon.sigma"), RULE);
    writeFileSync(join(sandbox, "storage", "artifacts", "rules", "other-ring.sigma"), OTHER);
    process.chdir(sandbox);
    active.loadActiveManifest.mockResolvedValue(
      manifestWith([{ path: "rules/beacon.sigma", sha256: sha(RULE) }])
    );
  });

  afterEach(() => {
    process.chdir(originalCwd);
    rmSync(sandbox, { recursive: true, force: true });
  });

  it("serves a file its manifest lists", async () => {
    const res = await call(`path=rules/beacon.sigma&sha256=${sha(RULE)}`);
    expect(res.status).toBe(200);
    expect(Buffer.from(await res.arrayBuffer())).toEqual(RULE);
  });

  it("refuses a file that exists in storage but is not in the agent's manifest", async () => {
    const res = await call(`path=rules/other-ring.sigma&sha256=${sha(OTHER)}`);
    expect(res.status).toBe(404);
  });

  it("refuses everything when the agent has no active release", async () => {
    active.loadActiveManifest.mockResolvedValue({
      ok: false,
      status: 404,
      error: "No content release available for ring",
    });
    expect((await call("path=rules/beacon.sigma")).status).toBe(404);
  });

  it("rejects a requested hash that is not the manifest's", async () => {
    const res = await call(`path=rules/beacon.sigma&sha256=${"0".repeat(64)}`);
    expect(res.status).toBe(409);
  });

  it("does not send a stored file that no longer matches the signed hash", async () => {
    writeFileSync(join(sandbox, "storage", "artifacts", "rules", "beacon.sigma"), "tampered");
    const res = await call(`path=rules/beacon.sigma&sha256=${sha(RULE)}`);
    expect(res.status).toBe(502);
  });

  it("does not follow a manifest entry that escapes the artifacts directory", async () => {
    active.loadActiveManifest.mockResolvedValue(
      manifestWith([{ path: "../manifests/secret.json", sha256: sha(RULE) }])
    );
    expect((await call("path=../manifests/secret.json")).status).toBe(400);
  });

  it("answers a missing path parameter with 400", async () => {
    expect((await call("")).status).toBe(400);
  });
});
