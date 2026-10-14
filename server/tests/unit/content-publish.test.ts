import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createHash } from "crypto";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join } from "path";

// Route logic runs against a mocked Prisma client, so these need no database.
const db = vi.hoisted(() => ({
  contentRelease: { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() },
  auditLog: { create: vi.fn() },
  member: { findFirst: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));

import { POST as publish } from "@/app/api/content/release/route";
import { POST as rollback } from "@/app/api/content/rollback/route";

const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

const RULE_V2 = Buffer.from("title: rule as of release 2\n");
const RULE_V4 = Buffer.from("title: rule as modified by release 4\n");
const OTHER = Buffer.from("title: another rule\n");

let originalCwd: string;
let sandbox: string;

function manifestFor(overrides: Record<string, unknown> = {}) {
  return Buffer.from(
    JSON.stringify({
      schema_version: 1,
      release_version: 5,
      ring: "canary_0",
      released_at: "2026-10-12T09:30:00Z",
      entries: [
        { path: "rules/x.sigma", type: "rule", sha256: sha(RULE_V2), size: RULE_V2.length },
        { path: "rules/y.sigma", type: "rule", sha256: sha(OTHER), size: OTHER.length },
      ],
      signature: "00",
      ...overrides,
    })
  );
}

/** Puts a manifest at storage://manifests/<name> and the given artifacts under storage/artifacts. */
function store(manifest: Buffer, artifacts: Record<string, Buffer>, name = "content-canary_0-v5.json") {
  writeFileSync(join(sandbox, "storage", "manifests", name), manifest);
  for (const [p, bytes] of Object.entries(artifacts)) {
    mkdirSync(join(sandbox, "storage", "artifacts", p, ".."), { recursive: true });
    writeFileSync(join(sandbox, "storage", "artifacts", p), bytes);
  }
}

const GOOD_ARTIFACTS = { "rules/x.sigma": RULE_V2, "rules/y.sigma": OTHER };

function post(body: unknown) {
  return new NextRequest("http://localhost/api/content/release", {
    method: "POST",
    headers: { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function publishBody(manifest: Buffer, overrides: Record<string, unknown> = {}) {
  return {
    ring: "canary_0",
    manifestUrl: "storage://manifests/content-canary_0-v5.json",
    manifestSha256: sha(manifest),
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  originalCwd = process.cwd();
  sandbox = join(originalCwd, ".test-sandbox-content-publish");
  mkdirSync(join(sandbox, "storage", "manifests"), { recursive: true });
  mkdirSync(join(sandbox, "storage", "artifacts"), { recursive: true });
  process.chdir(sandbox);
  // The ring's highest release is 4 (rolled back): the next number is 5.
  db.contentRelease.findFirst.mockResolvedValue({ releaseVersion: 4, status: "rolled_back" });
  db.contentRelease.create.mockImplementation(async ({ data }) => ({ id: "r5", ...data }));
  db.auditLog.create.mockResolvedValue({});
  // The caller is the tenant's owner by default (#803); tests of the admin check itself
  // override this.
  db.member.findFirst.mockResolvedValue({ role: "owner" });
});

afterEach(() => {
  process.chdir(originalCwd);
  rmSync(sandbox, { recursive: true, force: true });
});

describe("POST /api/content/release: nothing is published that an agent could not apply (#665)", () => {
  it("publishes a release whose manifest, number, ring and artifacts all check out", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(200);
    expect(db.contentRelease.create).toHaveBeenCalledOnce();
    expect(db.contentRelease.create.mock.calls[0][0].data.releaseVersion).toBe(5);
    expect(db.auditLog.create).toHaveBeenCalledOnce();
  });

  it("numbers the release after the ring's highest, rolled-back releases included", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    await publish(post(publishBody(manifest)));
    // No status filter: a rolled-back or halted release still owns its number.
    expect(db.contentRelease.findFirst).toHaveBeenCalledWith({
      where: { tenantId: "t1", ring: "canary_0" },
      orderBy: { releaseVersion: "desc" },
    });
  });

  it("refuses a manifest that carries another number than the one the control plane will assign", async () => {
    // Otherwise every agent of the ring gets a 502 when the manifest is served.
    const manifest = manifestFor({ release_version: 7 });
    store(manifest, GOOD_ARTIFACTS);
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(422);
    const body = await res.json();
    expect(body.error).toContain("5");
    expect(body.error).toContain("7");
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("refuses a manifest that lists nothing: an empty one would wipe every agent of the ring", async () => {
    const manifest = manifestFor({ entries: [] });
    store(manifest, {});
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(422);
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("refuses a manifest for another ring than the one it is published to", async () => {
    const manifest = manifestFor({ ring: "prod" });
    store(manifest, GOOD_ARTIFACTS);
    expect((await publish(post(publishBody(manifest)))).status).toBe(422);
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("refuses a manifest that does not hash to the value it is published with", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    const res = await publish(post(publishBody(manifest, { manifestSha256: "c".repeat(64) })));
    expect(res.status).toBe(422);
  });

  it("refuses a release whose artifact is not in the store", async () => {
    const manifest = manifestFor();
    store(manifest, { "rules/x.sigma": RULE_V2 }); // rules/y.sigma missing
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(422);
    expect((await res.json()).error).toContain("rules/y.sigma");
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("refuses a corrective release over a modified path until the earlier bytes are back in the store", async () => {
    // Release 4 changed rules/x.sigma. The store is keyed by path and shared across releases,
    // so it holds release 4's bytes; the corrective release lists release 2's hash for that
    // path. Published anyway, every agent on release 4 would get a 502 on that fetch, pruning
    // would never run and the bad rule would stay (review of #782).
    const manifest = manifestFor(); // lists RULE_V2's hash for rules/x.sigma
    store(manifest, { "rules/x.sigma": RULE_V4, "rules/y.sigma": OTHER });
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(422);
    const { error } = await res.json();
    expect(error).toContain("rules/x.sigma");
    expect(error).toMatch(/earlier bytes|put .* back/i);
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });

  it("publishes that corrective release once the earlier bytes have been put back", async () => {
    const manifest = manifestFor();
    store(manifest, { "rules/x.sigma": RULE_V4, "rules/y.sigma": OTHER });
    writeFileSync(join(sandbox, "storage", "artifacts", "rules/x.sigma"), RULE_V2); // restored
    expect((await publish(post(publishBody(manifest)))).status).toBe(200);
  });

  it("refuses an entry path that would leave the store", async () => {
    const manifest = manifestFor({
      entries: [{ path: "../../etc/passwd", type: "rule", sha256: sha(OTHER), size: 1 }],
    });
    store(manifest, {});
    expect((await publish(post(publishBody(manifest)))).status).toBe(422);
  });

  it("answers 409, not 500, when a concurrent publish took the number first", async () => {
    // Two publishes read the same highest release; the unique (tenant, ring, version) row
    // makes the second `create` fail. The binary release route already says so with a 409.
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    db.contentRelease.create.mockRejectedValue(Object.assign(new Error("unique"), { code: "P2002" }));
    const res = await publish(post(publishBody(manifest)));
    expect(res.status).toBe(409);
    expect(db.auditLog.create).not.toHaveBeenCalled();
  });

  it("without a tenant context it is not served", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    const res = await publish(
      new NextRequest("http://localhost/api/content/release", {
        method: "POST",
        body: JSON.stringify(publishBody(manifest)),
      })
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(db.contentRelease.create).not.toHaveBeenCalled();
  });
});

describe("POST /api/content/rollback: it says what it does not do (#665)", () => {
  function rollbackReq() {
    return new NextRequest("http://localhost/api/content/rollback", {
      method: "POST",
      headers: { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" },
      body: JSON.stringify({ ring: "canary_0", reason: "bad rule" }),
    });
  }

  it("names the corrective release after the ring's highest release, rolled-back ones included, and audits it", async () => {
    db.contentRelease.findFirst
      .mockResolvedValueOnce({ id: "r4", releaseVersion: 4, status: "active" }) // current
      .mockResolvedValueOnce({ id: "r2", releaseVersion: 2, status: "active" }) // target
      .mockResolvedValueOnce({ releaseVersion: 4 }); // highest of the ring
    db.contentRelease.update.mockImplementation(async ({ where, data }) => ({ id: where.id, ...data }));

    const res = await rollback(rollbackReq());

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.correctiveRelease.releaseVersion).toBe(5);
    expect(body.correctiveRelease.restoreVersion).toBe(2);
    expect(db.auditLog.create.mock.calls[0][0].data.details.correctiveReleaseVersion).toBe(5);
    // The highest-release lookup has no status filter.
    expect(db.contentRelease.findFirst.mock.calls[2][0]).toEqual({
      where: { tenantId: "t1", ring: "canary_0" },
      orderBy: { releaseVersion: "desc" },
      select: { releaseVersion: true },
    });
  });
});

describe("content/release and content/rollback require the admin role (#803)", () => {
  function rollbackReq() {
    return new NextRequest("http://localhost/api/content/rollback", {
      method: "POST",
      headers: { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" },
      body: JSON.stringify({ ring: "canary_0", reason: "bad rule" }),
    });
  }

  it("refuses a plain member on both routes, before either reads its body", async () => {
    db.member.findFirst.mockResolvedValue({ role: "member" });
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);

    const publishRes = await publish(post(publishBody(manifest)));
    expect(publishRes.status).toBe(403);
    expect(db.contentRelease.create).not.toHaveBeenCalled();

    const rollbackRes = await rollback(rollbackReq());
    expect(rollbackRes.status).toBe(403);
    expect(db.contentRelease.update).not.toHaveBeenCalled();
  });

  it("refuses a caller with no membership row at all", async () => {
    db.member.findFirst.mockResolvedValue(null);
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    expect((await publish(post(publishBody(manifest)))).status).toBe(403);
  });

  it("accepts an admin member, not only an owner", async () => {
    db.member.findFirst.mockResolvedValue({ role: "admin" });
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    expect((await publish(post(publishBody(manifest)))).status).toBe(200);
  });

  it("looks the membership up by the caller's own tenant and user id", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    await publish(post(publishBody(manifest)));
    expect(db.member.findFirst).toHaveBeenCalledWith({
      where: { organizationId: "t1", userId: "u1" },
      select: { role: true },
    });
  });
});

describe("content/release marks a corrective release in its audit entry (#803)", () => {
  it("records restoresVersion and corrective:true when the publish names the release it restores", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    await publish(post(publishBody(manifest, { restoresVersion: 2 })));
    const details = db.auditLog.create.mock.calls[0][0].data.details;
    expect(details.corrective).toBe(true);
    expect(details.restoresVersion).toBe(2);
  });

  it("records corrective:false for an ordinary release", async () => {
    const manifest = manifestFor();
    store(manifest, GOOD_ARTIFACTS);
    await publish(post(publishBody(manifest)));
    const details = db.auditLog.create.mock.calls[0][0].data.details;
    expect(details.corrective).toBe(false);
    expect(details.restoresVersion).toBeNull();
  });
});
